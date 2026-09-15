#!/usr/bin/env python3
"""Interactive cdxgen -> Dependency-Track workflow for Windows.

The script follows SBOM.md:
  - source project: cdxgen recursive project scan
  - firmware: scan an already extracted readable rootfs with -t rootfs
  - configuration directory: recursive cdxgen scan
  - CycloneDX specification: 1.6
  - output: <workdir>\\output\\<kind>\\bom.cdx.json

The Dependency-Track API key is stored using Windows DPAPI. The protected
value can only be decrypted by the same Windows user on the same machine.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import getpass
import json
import os
import subprocess
import sys
import time
import uuid
import webbrowser
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


# In a PyInstaller one-file build, __file__ points to the temporary extraction
# directory. Keep persistent configuration beside the script or EXE instead.
SCRIPT_DIR = (
    Path(sys.executable).resolve().parent
    if getattr(sys, "frozen", False)
    else Path(__file__).resolve().parent
)
CONFIG_PATH = SCRIPT_DIR / "sbom_scan_config.json"
CYCLONEDX_SPEC_VERSION = "1.6"

TYPE_INFO = {
    "1": ("source", "源码项目", "源码项目目录，或源码依赖文件所在目录"),
    "2": ("firmware", "固件包", "已经解包的可读取 rootfs 目录"),
    "3": ("config", "配置文件", "配置文件或依赖清单所在目录"),
}


class WorkflowError(RuntimeError):
    """A user-actionable workflow error."""


def clean_input_path(value: str) -> Path:
    """Convert a pasted Windows path into a Path."""
    return Path(value.strip().strip('"').strip("'")).expanduser()


def normalize_dt_url(value: str) -> str:
    """Normalize a Dependency-Track frontend/base URL."""
    base = value.strip().rstrip("/")
    if base.lower().endswith("/api"):
        base = base[:-4].rstrip("/")
    return base


def prompt_nonempty(message: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"{message}{suffix}: ").strip()
        if value:
            return value
        if default:
            return default
        print("不能为空，请重新输入。")


def prompt_existing_file(message: str, default: Path | None = None) -> Path:
    while True:
        default_text = str(default) if default else None
        path = clean_input_path(prompt_nonempty(message, default_text))
        if path.is_file():
            return path.resolve()
        print(f"文件不存在：{path}")


def prompt_workdir(default: Path) -> Path:
    while True:
        path = clean_input_path(prompt_nonempty("工作目录", str(default)))
        try:
            path.mkdir(parents=True, exist_ok=True)
            return path.resolve()
        except OSError as exc:
            print(f"无法创建工作目录：{exc}")


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.c_uint32),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _to_data_blob(value: bytes) -> tuple[_DataBlob, Any]:
    buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
    blob = _DataBlob(
        cbData=len(value),
        pbData=ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
    )
    return blob, buffer


def _dpapi_protect(value: bytes) -> bytes:
    if os.name != "nt":
        raise WorkflowError("API Key 加密功能仅支持 Windows。")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.c_wchar_p,
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptProtectData.restype = ctypes.c_bool
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    input_blob, input_buffer = _to_data_blob(value)
    output_blob = _DataBlob()
    if not crypt32.CryptProtectData(
        ctypes.byref(input_blob), None, None, None, None, 0, ctypes.byref(output_blob)
    ):
        raise WorkflowError(f"Windows DPAPI 加密失败，错误码：{ctypes.GetLastError()}")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree(output_blob.pbData)
        del input_buffer


def _dpapi_unprotect(value: bytes) -> bytes:
    if os.name != "nt":
        raise WorkflowError("API Key 解密功能仅支持 Windows。")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptUnprotectData.restype = ctypes.c_bool
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    input_blob, input_buffer = _to_data_blob(value)
    output_blob = _DataBlob()
    description = ctypes.c_wchar_p()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(input_blob),
        ctypes.byref(description),
        None,
        None,
        None,
        0,
        ctypes.byref(output_blob),
    ):
        raise WorkflowError(f"Windows DPAPI 解密失败，错误码：{ctypes.GetLastError()}")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree(output_blob.pbData)
        if description:
            kernel32.LocalFree(description)
        del input_buffer


def protect_api_key(api_key: str) -> str:
    protected = _dpapi_protect(api_key.encode("utf-8"))
    return base64.b64encode(protected).decode("ascii")


def unprotect_api_key(protected_value: str) -> str:
    encrypted = base64.b64decode(protected_value.encode("ascii"))
    return _dpapi_unprotect(encrypted).decode("utf-8")


def save_config(config: dict[str, Any]) -> None:
    CONFIG_PATH.write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.is_file():
        return {}
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowError(f"无法读取配置文件 {CONFIG_PATH}：{exc}") from exc
    if not isinstance(data, dict):
        raise WorkflowError(f"配置文件格式错误：{CONFIG_PATH}")
    return data


def setup_or_load_config() -> tuple[dict[str, Any], str]:
    config = load_config()
    default_cdxgen = SCRIPT_DIR / "cdxgen-windows-amd64.exe"
    default_workdir = SCRIPT_DIR

    cdxgen_value = config.get("cdxgen")
    workdir_value = config.get("workdir")
    dt_url_value = config.get("dependency_track_url")

    needs_setup = not all(
        isinstance(value, str) and value.strip()
        for value in (cdxgen_value, workdir_value, dt_url_value)
    )

    if needs_setup:
        print("首次使用，设置 cdxgen、工作目录和 Dependency-Track。")
        cdxgen = prompt_existing_file(
            "cdxgen 可执行文件路径",
            default_cdxgen if default_cdxgen.is_file() else None,
        )
        workdir = prompt_workdir(Path(workdir_value) if workdir_value else default_workdir)
        dt_url = normalize_dt_url(
            prompt_nonempty(
                "Dependency-Track 地址",
                str(dt_url_value) if dt_url_value else "http://127.0.0.1:8080",
            )
        )
    else:
        cdxgen = clean_input_path(str(cdxgen_value)).resolve()
        workdir = clean_input_path(str(workdir_value)).resolve()
        dt_url = normalize_dt_url(str(dt_url_value))
        if not cdxgen.is_file():
            cdxgen = prompt_existing_file("cdxgen 可执行文件路径", default_cdxgen)
        workdir.mkdir(parents=True, exist_ok=True)

    api_key = os.environ.get("DT_API_KEY", "").strip()
    if not api_key:
        protected = config.get("api_key_protected")
        if isinstance(protected, str) and protected.strip():
            try:
                api_key = unprotect_api_key(protected)
            except WorkflowError:
                print("已保存的 API Key 无法在当前 Windows 用户下解密。")

    if not api_key:
        print("请输入 Dependency-Track API Key。输入时不会显示字符。")
        api_key = getpass.getpass("API Key: ").strip()
        if not api_key:
            raise WorkflowError("API Key 不能为空。")

    new_config = {
        "cdxgen": str(cdxgen),
        "workdir": str(workdir),
        "dependency_track_url": dt_url,
        "api_key_protected": protect_api_key(api_key),
    }
    if new_config != config:
        save_config(new_config)
        print(f"配置已保存：{CONFIG_PATH}")

    return new_config, api_key


def choose_scan_type() -> tuple[str, str, str] | None:
    print("\n请选择处理对象：")
    for key, (_, label, description) in TYPE_INFO.items():
        print(f"  {key}. {label}（{description}）")
    print("  0. 退出")
    choice = input("选择: ").strip()
    if choice == "0":
        return None
    if choice not in TYPE_INFO:
        print("无效选择。")
        return choose_scan_type()
    return TYPE_INFO[choice]


def choose_input_path(kind: str, description: str) -> Path | None:
    raw = input(f"请输入{description}路径（输入 q 返回）：").strip()
    if raw.lower() in {"q", "quit", "exit"}:
        return None
    path = clean_input_path(raw)
    if not path.exists():
        raise WorkflowError(f"输入路径不存在：{path}")

    if kind == "firmware":
        if not path.is_dir():
            raise WorkflowError(
                "固件扫描需要已经解包的 rootfs 目录。"
                "请先使用 Binwalk/7-Zip/EMBA/FACT 解包，再输入包含 bin、etc、lib、usr 等目录的 rootfs 路径。"
            )
        return path.resolve()

    if path.is_file():
        print(f"已输入文件，将扫描其所在目录：{path.parent}")
        return path.parent.resolve()
    return path.resolve()


def has_c_cpp_files(root: Path) -> bool:
    extensions = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}
    try:
        return any(item.is_file() and item.suffix.lower() in extensions for item in root.rglob("*"))
    except OSError:
        return False


def has_gradle_files(root: Path) -> bool:
    """Return whether the input tree contains files that trigger Gradle scanning."""
    gradle_names = {
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "gradlew",
        "gradlew.bat",
        "gradle-wrapper.properties",
    }
    try:
        return any(item.is_file() and item.name.lower() in gradle_names for item in root.rglob("*"))
    except OSError:
        return False


def run_cdxgen(
    cdxgen: Path,
    kind: str,
    scan_path: Path,
    output_path: Path,
    c_type: bool = False,
    exclude_gradle: bool = False,
) -> None:
    command = [str(cdxgen), "-r"]
    if kind == "firmware":
        command.extend(["-t", "rootfs"])
    elif c_type:
        command.extend(["-t", "c"])
    if exclude_gradle:
        command.extend(["--exclude-type", "gradle"])
    command.extend(
        [
            "--no-install-deps",
            "--spec-version",
            CYCLONEDX_SPEC_VERSION,
            "-o",
            str(output_path),
            str(scan_path),
        ]
    )

    print("\n开始生成 CycloneDX BOM：")
    print(subprocess.list2cmdline(command))
    result = subprocess.run(command, cwd=str(scan_path), check=False)
    if result.returncode != 0:
        raise WorkflowError(f"cdxgen 执行失败，退出码：{result.returncode}")
    if not output_path.is_file():
        raise WorkflowError(f"cdxgen 未生成输出文件：{output_path}")


def read_bom(output_path: Path) -> tuple[dict[str, Any], int]:
    try:
        bom = json.loads(output_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowError(f"BOM 不是有效 JSON：{output_path}：{exc}") from exc
    components = bom.get("components", [])
    if not isinstance(components, list):
        components = []
    return bom, len(components)


def ask_yes_no(message: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    answer = input(f"{message} [{suffix}]: ").strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes", "是"}


def make_multipart(
    fields: dict[str, str], file_field: str, file_path: Path
) -> tuple[str, bytes]:
    boundary = "----SBOMUpload" + uuid.uuid4().hex
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{value}\r\n"
            ).encode("utf-8")
        )

    chunks.append(
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{file_field}"; '
            f'filename="{file_path.name}"\r\n'
            "Content-Type: application/json\r\n\r\n"
        ).encode("utf-8")
    )
    chunks.append(file_path.read_bytes())
    chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode("ascii"))
    return boundary, b"".join(chunks)


def api_json(
    url: str,
    api_key: str,
    method: str = "GET",
    body: bytes | None = None,
    content_type: str | None = None,
) -> Any:
    headers = {
        "Accept": "application/json",
        "X-Api-Key": api_key,
        "User-Agent": "sbom-scan-upload/1.0",
    }
    if content_type:
        headers["Content-Type"] = content_type
    request = Request(url, data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=60) as response:
            raw = response.read()
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise WorkflowError(f"Dependency-Track API 返回 HTTP {exc.code}：{detail}") from exc
    except URLError as exc:
        raise WorkflowError(f"无法连接 Dependency-Track：{exc.reason}") from exc
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return raw.decode("utf-8", errors="replace")


def upload_bom(
    dt_url: str,
    api_key: str,
    project_name: str,
    project_version: str,
    bom_path: Path,
) -> dict[str, Any]:
    fields = {
        "autoCreate": "true",
        "projectName": project_name,
        "projectVersion": project_version,
    }
    boundary, body = make_multipart(fields, "bom", bom_path)
    result = api_json(
        f"{dt_url}/api/v1/bom",
        api_key,
        method="POST",
        body=body,
        content_type=f"multipart/form-data; boundary={boundary}",
    )
    if not isinstance(result, dict):
        raise WorkflowError(f"Dependency-Track 返回内容无法解析：{result}")
    return result


def wait_for_bom_processing(dt_url: str, api_key: str, token: str) -> None:
    """Wait briefly using the token endpoint exposed by the user's DT instance."""
    endpoint = f"{dt_url}/api/v1/bom/token/{token}"
    deadline = time.monotonic() + 90
    printed_wait = False
    while time.monotonic() < deadline:
        try:
            result = api_json(endpoint, api_key)
        except WorkflowError:
            return
        processing: bool | None = None
        if isinstance(result, bool):
            processing = result
        elif isinstance(result, dict):
            value = result.get("processing")
            if isinstance(value, bool):
                processing = value
            else:
                value = result.get("isProcessing")
                if isinstance(value, bool):
                    processing = value
        if processing is False:
            if printed_wait:
                print()
            print("Dependency-Track 已完成该 BOM 的队列处理。")
            return
        if not printed_wait:
            print("Dependency-Track 正在处理 BOM", end="", flush=True)
            printed_wait = True
        print(".", end="", flush=True)
        time.sleep(2)
    if printed_wait:
        print()
    print("BOM 处理仍可能在后台进行，请稍后刷新项目页面。")


def lookup_project(
    dt_url: str, api_key: str, project_name: str, project_version: str
) -> dict[str, Any] | None:
    query = urlencode({"name": project_name, "version": project_version})
    endpoint = f"{dt_url}/api/v1/project/lookup?{query}"
    try:
        result = api_json(endpoint, api_key)
    except WorkflowError:
        return None
    return result if isinstance(result, dict) else None


def get_project_links(
    dt_url: str,
    api_key: str,
    project_name: str,
    project_version: str,
) -> tuple[str, str | None]:
    projects_url = f"{dt_url}/projects"
    deadline = time.monotonic() + 30
    project: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        project = lookup_project(dt_url, api_key, project_name, project_version)
        if project:
            break
        time.sleep(2)

    project_uuid = project.get("uuid") if project else None
    if isinstance(project_uuid, str) and project_uuid:
        project_url = f"{dt_url}/projects/{project_uuid}"
        components_url = f"{project_url}/components"
        return project_url, components_url
    return projects_url, None


def process_one(
    config: dict[str, Any],
    api_key: str,
    kind: str,
    label: str,
    input_description: str,
) -> None:
    cdxgen = clean_input_path(str(config["cdxgen"]))
    workdir = clean_input_path(str(config["workdir"]))
    dt_url = normalize_dt_url(str(config["dependency_track_url"]))

    scan_path = choose_input_path(kind, input_description)
    if scan_path is None:
        return

    output_dir = workdir / "output" / kind
    output_dir.mkdir(parents=True, exist_ok=True)
    bom_path = output_dir / "bom.cdx.json"

    default_name = scan_path.name or kind
    project_name = prompt_nonempty("Dependency-Track 项目名称", default_name)
    project_version = prompt_nonempty("Dependency-Track 项目版本", "1.0.0")

    exclude_gradle = False
    if kind == "source" and has_gradle_files(scan_path):
        print(
            "\n检测到 Gradle 工程文件。包含 Gradle 依赖时，cdxgen 可能需要下载项目指定的 Gradle Wrapper。"
        )
        include_gradle = ask_yes_no(
            "是否包含 Gradle 依赖（可能需要联网下载）",
            False,
        )
        exclude_gradle = not include_gradle
        if exclude_gradle:
            print("本次扫描将跳过 Gradle 类型，不会收集 Gradle 项目的依赖。")

    run_cdxgen(cdxgen, kind, scan_path, bom_path, exclude_gradle=exclude_gradle)
    _, component_count = read_bom(bom_path)

    if kind == "source" and component_count == 0 and has_c_cpp_files(scan_path):
        if ask_yes_no("未识别到组件，检测到 C/C++ 文件，是否使用 -t c 重试", True):
            run_cdxgen(
                cdxgen,
                kind,
                scan_path,
                bom_path,
                c_type=True,
                exclude_gradle=exclude_gradle,
            )
            _, component_count = read_bom(bom_path)

    print(f"\nBOM 输出：{bom_path}")
    print(f"组件数量：{component_count}")
    if component_count == 0:
        print(
            "注意：当前 BOM 没有组件。纯 INI、CONF、YAML、XML 等配置文件通常不会生成组件。"
        )
        if not ask_yes_no("仍然上传这个 0 组件 BOM", False):
            print("已停止上传。")
            return

    print("\n正在上传到 Dependency-Track...")
    response = upload_bom(
        dt_url,
        api_key,
        project_name,
        project_version,
        bom_path,
    )
    token = response.get("token")
    if isinstance(token, str) and token:
        print("Dependency-Track 已接收上传请求。")
        wait_for_bom_processing(dt_url, api_key, token)
    else:
        print(f"Dependency-Track 返回：{json.dumps(response, ensure_ascii=False)}")

    project_url, components_url = get_project_links(
        dt_url, api_key, project_name, project_version
    )
    print("\n处理完成。")
    print(f"项目页面：{project_url}")
    if components_url:
        print(f"组件页面：{components_url}")
    print(f"项目列表：{dt_url}/projects")

    if ask_yes_no("是否打开项目页面", True):
        webbrowser.open(project_url)


def main() -> int:
    parser = argparse.ArgumentParser(description="cdxgen 扫描并上传 Dependency-Track")
    parser.add_argument(
        "--reset-config",
        action="store_true",
        help=f"删除当前配置并在下次运行时重新询问（配置文件：{CONFIG_PATH}）",
    )
    args = parser.parse_args()

    if args.reset_config and CONFIG_PATH.exists():
        CONFIG_PATH.unlink()
        print(f"已删除配置：{CONFIG_PATH}")

    try:
        config, api_key = setup_or_load_config()
    except (WorkflowError, KeyboardInterrupt) as exc:
        print(f"\n程序未完成：{exc}")
        return 1

    print(f"\ncdxgen：{config['cdxgen']}")
    print(f"工作目录：{config['workdir']}")
    print(f"Dependency-Track：{config['dependency_track_url']}")

    while True:
        selected = choose_scan_type()
        if selected is None:
            return 0
        kind, label, description = selected
        print(f"\n当前处理对象：{label}")
        try:
            process_one(config, api_key, kind, label, description)
        except KeyboardInterrupt:
            print("\n已取消当前操作。")
        except (WorkflowError, OSError) as exc:
            print(f"\n处理失败：{exc}")
        if not ask_yes_no("是否继续处理另一个对象", True):
            return 0


if __name__ == "__main__":
    sys.exit(main())

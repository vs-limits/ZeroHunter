"""FastAPI 应用入口。

启动方式：
    cd backend
    uvicorn app.server.app:app --reload --port 8765
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, StreamingResponse
from pydantic import BaseModel

from app.server import artifacts as art
from app.server import content as cnt
from app.server import import_jobs
from app.server import llms as llms_mod
from app.server import observability as obs
from app.server import projects as proj
from app.server import runner as run_mod
from app.server import scans as scans_mod
from app.server import vulnerabilities as vulns_mod
from app.server.vulnerability_export import content_disposition
from app.server.vulnerability_export import EXPORT_SECTION_KEYS


app = FastAPI(title="DefectMine 管理平台", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _on_startup() -> None:
    from app.server import scheduler

    scheduler.start_scheduler()


@app.on_event("shutdown")
def _on_shutdown() -> None:
    from app.server import scheduler

    scheduler.stop_scheduler()


# --------- 项目 ---------


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True}


class MiniConfigPayload(BaseModel):
    thinking: bool | None = None
    reasoning_effort: str | None = None
    top_k: int | None = None
    min_p: float | None = None
    repetition_penalty: float | None = None


class LlmPayload(BaseModel):
    name: str
    notes: str = ""
    base_url: str
    api_key: str
    model_name: str
    protocol: str
    config_type: str = "standard"
    mini_config: MiniConfigPayload | None = None


class LlmUpdatePayload(BaseModel):
    name: str
    notes: str = ""
    base_url: str
    api_key: str | None = None
    model_name: str
    protocol: str
    config_type: str | None = None
    mini_config: MiniConfigPayload | None = None


class LlmSelectPayload(BaseModel):
    llm_id: str


class LlmTestPayload(BaseModel):
    llm_id: str | None = None
    name: str | None = None
    notes: str = ""
    base_url: str | None = None
    api_key: str | None = None
    model_name: str | None = None
    protocol: str | None = None
    config_type: str | None = None
    mini_config: MiniConfigPayload | None = None


class LlmConcurrentTestPayload(LlmTestPayload):
    count: int = 5
    success_threshold: int | None = None


@app.get("/api/llms")
def llms_list() -> dict[str, Any]:
    return llms_mod.list_llms()


@app.post("/api/llms")
def llms_create(payload: LlmPayload) -> dict[str, Any]:
    try:
        return llms_mod.create_llm(payload.model_dump())
    except ValueError as exc:
        raise _err(exc) from exc


@app.patch("/api/llms/{llm_id}")
def llms_update(llm_id: str, payload: LlmUpdatePayload) -> dict[str, Any]:
    try:
        return llms_mod.update_llm(llm_id, payload.model_dump(exclude_none=True))
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.delete("/api/llms/{llm_id}")
def llms_delete(llm_id: str) -> dict[str, Any]:
    try:
        return llms_mod.delete_llm(llm_id)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.post("/api/llms/select")
def llms_select(payload: LlmSelectPayload) -> dict[str, Any]:
    try:
        return llms_mod.select_llm(payload.llm_id)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.post("/api/llms/test")
def llms_test(payload: LlmTestPayload) -> dict[str, Any]:
    try:
        return llms_mod.test_llm(payload.model_dump(exclude_none=True))
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/api/llms/test-concurrent")
def llms_test_concurrent(payload: LlmConcurrentTestPayload) -> dict[str, Any]:
    try:
        return llms_mod.test_llm_concurrent(payload.model_dump(exclude_none=True))
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/api/projects")
def projects_list(
    summary: bool = Query(default=False, description="true 时跳过各版本 scan 产物摘要，加快首屏"),
) -> dict[str, Any]:
    return {"items": proj.list_projects(include_scan_summaries=not summary)}


class CreateProjectPayload(BaseModel):
    source: str
    owner: str
    repo: str
    name: str = ""
    notes: str = ""


class UpdateProjectPayload(BaseModel):
    name: str | None = None
    notes: str | None = None
    description: str | None = None
    tags: list[str] | None = None
    audit_status: str | None = None
    favorite: bool | None = None
    project_profile: dict[str, Any] | None = None


class CreateVersionPayload(BaseModel):
    kind: str = "manual"  # manual | copy | local
    version: str
    name: str = ""
    notes: str = ""
    role: str = "baseline"
    overwrite: bool = False
    source_version: str | None = None
    local_path: str | None = None


class UpdateVersionPayload(BaseModel):
    name: str | None = None
    notes: str | None = None
    role: str | None = None


class GitImportPayload(BaseModel):
    git_url: str
    ref: str = "HEAD"
    version: str = ""
    name: str = ""
    notes: str = ""
    role: str = "baseline"
    overwrite: bool = False
    depth: int | None = None
    single_branch: bool = False
    recurse_submodules: bool = False


class SettingsPayload(BaseModel):
    vulnerability_tags: list[str] | None = None
    environment_file_presets: list[str] | None = None
    poc_file_presets: list[str] | None = None
    poc_parameter_presets: list[dict[str, Any]] | None = None


class VulnerabilityPayload(BaseModel):
    name: str | None = None
    details: str | None = None
    tags: list[str] | None = None
    location: str | None = None
    affected_version: str | None = None
    severity: str | None = None
    status: str | None = None
    cve: str | None = None
    references: list[str] | None = None
    source: str | None = None
    links: dict[str, Any] | None = None
    source_finding: dict[str, Any] | None = None
    environment_commands: dict[str, Any] | None = None
    reproduction: str | None = None
    poc_commands: dict[str, Any] | None = None


class VulnerabilityFromFindingPayload(BaseModel):
    project_path: str
    scan_id: str
    chain_id: str
    duplicate: bool = False


class VulnerabilityAiAnalyzePayload(BaseModel):
    section: str


class VulnerabilityFilePayload(BaseModel):
    section: str
    filename: str
    content: str = ""


class VulnerabilityFileRenamePayload(BaseModel):
    section: str
    filename: str
    new_filename: str


@app.get("/api/settings")
def settings_get() -> dict[str, Any]:
    return vulns_mod.read_settings()


@app.patch("/api/settings")
def settings_update(payload: SettingsPayload) -> dict[str, Any]:
    try:
        return vulns_mod.update_settings(payload.model_dump(exclude_unset=True))
    except ValueError as exc:
        raise _err(exc) from exc


@app.post("/api/projects")
def projects_create(payload: CreateProjectPayload) -> dict[str, Any]:
    try:
        return proj.create_project(
            source=payload.source,
            owner=payload.owner,
            repo=payload.repo,
            name=payload.name,
            notes=payload.notes,
        )
    except (FileExistsError, FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.patch("/api/projects/{src}/{owner}/{repo}")
def projects_update(src: str, owner: str, repo: str, payload: UpdateProjectPayload) -> dict[str, Any]:
    try:
        return proj.update_project(
            src,
            owner,
            repo,
            name=payload.name,
            notes=payload.notes,
            description=payload.description,
            tags=payload.tags,
            audit_status=payload.audit_status,
            favorite=payload.favorite,
            project_profile=payload.project_profile,
        )
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.post("/api/projects/{src}/{owner}/{repo}/versions")
def versions_create(src: str, owner: str, repo: str, payload: CreateVersionPayload) -> dict[str, Any]:
    try:
        return proj.create_version(
            src,
            owner,
            repo,
            kind=payload.kind,
            version=payload.version,
            name=payload.name,
            notes=payload.notes,
            role=payload.role,
            overwrite=payload.overwrite,
            source_version=payload.source_version,
            local_path=payload.local_path,
        )
    except (FileExistsError, FileNotFoundError, ValueError, NotADirectoryError) as exc:
        raise _err(exc) from exc


@app.patch("/api/projects/{src}/{owner}/{repo}/versions/{version}")
def versions_update(
    src: str,
    owner: str,
    repo: str,
    version: str,
    payload: UpdateVersionPayload,
) -> dict[str, Any]:
    try:
        return proj.update_version(
            src,
            owner,
            repo,
            version,
            name=payload.name,
            notes=payload.notes,
            role=payload.role,
        )
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.delete("/api/projects/{src}/{owner}/{repo}/versions/{version}")
def versions_delete(src: str, owner: str, repo: str, version: str) -> dict[str, Any]:
    try:
        meta = proj.delete_version(src, owner, repo, version)
        return {"ok": True, "version": version, "meta": meta}
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.post("/api/projects/{src}/{owner}/{repo}/versions/git-import")
def versions_git_import(src: str, owner: str, repo: str, payload: GitImportPayload) -> dict[str, Any]:
    try:
        return import_jobs.start_git_import(src, owner, repo, payload.model_dump())
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/projects/{src}/{owner}/{repo}/versions/git-refs")
def versions_git_refs(
    src: str,
    owner: str,
    repo: str,
    git_url: str = Query(default=""),
    refresh: bool = Query(default=False),
) -> dict[str, Any]:
    try:
        return import_jobs.list_git_refs(
            src,
            owner,
            repo,
            git_url=git_url,
            refresh=refresh,
        )
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/projects/{src}/{owner}/{repo}/vulnerabilities")
def vulnerabilities_list(src: str, owner: str, repo: str) -> dict[str, Any]:
    try:
        return {"items": vulns_mod.list_vulnerabilities(src, owner, repo)}
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.post("/api/projects/{src}/{owner}/{repo}/vulnerabilities")
def vulnerabilities_create(
    src: str,
    owner: str,
    repo: str,
    payload: VulnerabilityPayload,
) -> dict[str, Any]:
    try:
        return vulns_mod.create_vulnerability(
            src,
            owner,
            repo,
            payload.model_dump(exclude_unset=True),
        )
    except (FileExistsError, FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.post("/api/projects/{src}/{owner}/{repo}/vulnerabilities/from-finding")
def vulnerabilities_from_finding(
    src: str,
    owner: str,
    repo: str,
    payload: VulnerabilityFromFindingPayload,
) -> dict[str, Any]:
    try:
        return vulns_mod.convert_finding_to_vulnerability(
            src,
            owner,
            repo,
            project_path=payload.project_path,
            scan_id=payload.scan_id,
            chain_id=payload.chain_id,
            duplicate=payload.duplicate,
        )
    except (FileExistsError, FileNotFoundError, KeyError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/projects/{src}/{owner}/{repo}/link-targets")
def project_link_targets(src: str, owner: str, repo: str) -> dict[str, Any]:
    try:
        return vulns_mod.link_targets(src, owner, repo)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/projects/{src}/{owner}/{repo}/vulnerabilities/{vulnerability_id}")
def vulnerabilities_get(src: str, owner: str, repo: str, vulnerability_id: str) -> dict[str, Any]:
    try:
        return vulns_mod.get_vulnerability(src, owner, repo, vulnerability_id)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.post("/api/projects/{src}/{owner}/{repo}/vulnerabilities/{vulnerability_id}/ai/analyze")
def vulnerabilities_ai_analyze(
    src: str,
    owner: str,
    repo: str,
    vulnerability_id: str,
    payload: VulnerabilityAiAnalyzePayload,
) -> dict[str, Any]:
    try:
        return vulns_mod.analyze_vulnerability(
            src,
            owner,
            repo,
            vulnerability_id,
            payload.section,
        )
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/projects/{src}/{owner}/{repo}/vulnerabilities/{vulnerability_id}/export")
def vulnerabilities_export(
    src: str,
    owner: str,
    repo: str,
    vulnerability_id: str,
    format: str = Query(default="html"),
    sections: list[str] | None = Query(default=None, description="Export section keys"),
) -> Response:
    try:
        exported = vulns_mod.export_vulnerability(
            src,
            owner,
            repo,
            vulnerability_id,
            format,
            sections=sections,
        )
        return Response(
            content=exported["content"],
            media_type=exported["media_type"],
            headers={
                "Content-Disposition": content_disposition(exported["filename"]),
                "Cache-Control": "no-store",
            },
        )
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.patch("/api/projects/{src}/{owner}/{repo}/vulnerabilities/{vulnerability_id}")
def vulnerabilities_update(
    src: str,
    owner: str,
    repo: str,
    vulnerability_id: str,
    payload: VulnerabilityPayload,
) -> dict[str, Any]:
    try:
        return vulns_mod.update_vulnerability(
            src,
            owner,
            repo,
            vulnerability_id,
            payload.model_dump(exclude_unset=True),
        )
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.delete("/api/projects/{src}/{owner}/{repo}/vulnerabilities/{vulnerability_id}")
def vulnerabilities_delete(src: str, owner: str, repo: str, vulnerability_id: str) -> dict[str, Any]:
    try:
        meta = vulns_mod.delete_vulnerability(src, owner, repo, vulnerability_id)
        return {"ok": True, "vulnerability_id": vulnerability_id, "meta": meta}
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/projects/{src}/{owner}/{repo}/vulnerabilities/{vulnerability_id}/files")
def vulnerability_files_list(
    src: str,
    owner: str,
    repo: str,
    vulnerability_id: str,
    section: str,
) -> dict[str, Any]:
    try:
        return vulns_mod.list_files(src, owner, repo, vulnerability_id, section)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.put("/api/projects/{src}/{owner}/{repo}/vulnerabilities/{vulnerability_id}/files")
def vulnerability_files_write(
    src: str,
    owner: str,
    repo: str,
    vulnerability_id: str,
    payload: VulnerabilityFilePayload,
) -> dict[str, Any]:
    try:
        return vulns_mod.write_file(
            src,
            owner,
            repo,
            vulnerability_id,
            payload.section,
            payload.filename,
            payload.content,
        )
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.patch("/api/projects/{src}/{owner}/{repo}/vulnerabilities/{vulnerability_id}/files")
def vulnerability_files_rename(
    src: str,
    owner: str,
    repo: str,
    vulnerability_id: str,
    payload: VulnerabilityFileRenamePayload,
) -> dict[str, Any]:
    try:
        return vulns_mod.rename_file(
            src,
            owner,
            repo,
            vulnerability_id,
            payload.section,
            payload.filename,
            payload.new_filename,
        )
    except (FileExistsError, FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.delete("/api/projects/{src}/{owner}/{repo}/vulnerabilities/{vulnerability_id}/files")
def vulnerability_files_delete(
    src: str,
    owner: str,
    repo: str,
    vulnerability_id: str,
    section: str,
    filename: str,
) -> dict[str, Any]:
    try:
        return vulns_mod.delete_file(src, owner, repo, vulnerability_id, section, filename)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.post("/api/projects/{src}/{owner}/{repo}/vulnerabilities/{vulnerability_id}/assets")
async def vulnerability_assets_upload(
    src: str,
    owner: str,
    repo: str,
    vulnerability_id: str,
    file: UploadFile = File(...),
) -> dict[str, Any]:
    try:
        data = await file.read()
        return vulns_mod.save_asset(
            src,
            owner,
            repo,
            vulnerability_id,
            filename=file.filename or "asset",
            content_type=file.content_type,
            data=data,
        )
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/projects/{src}/{owner}/{repo}/vulnerabilities/{vulnerability_id}/assets/{filename}")
def vulnerability_assets_get(
    src: str,
    owner: str,
    repo: str,
    vulnerability_id: str,
    filename: str,
) -> FileResponse:
    try:
        path = vulns_mod.asset_path(src, owner, repo, vulnerability_id, filename)
        return FileResponse(path)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/imports/{job_id}")
def import_job_get(job_id: str) -> dict[str, Any]:
    job = import_jobs.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="import job not found")
    return job


@app.post("/api/imports/{job_id}/stop")
def import_job_stop(job_id: str) -> dict[str, Any]:
    return {"ok": import_jobs.stop_job(job_id), "job_id": job_id}


@app.post("/api/imports/{job_id}/retry")
def import_job_retry(job_id: str) -> dict[str, Any]:
    try:
        return import_jobs.retry_job(job_id)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/imports/{job_id}/stream")
async def import_job_stream(job_id: str) -> StreamingResponse:
    if import_jobs.get_job(job_id) is None:
        raise HTTPException(status_code=404, detail="import job not found")
    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    return StreamingResponse(import_jobs.stream_job(job_id), media_type="text/event-stream", headers=headers)


@app.get("/api/projects/{src}/{owner}/{repo}/{version}/runs")
def project_runs(src: str, owner: str, repo: str, version: str) -> dict[str, Any]:
    project_path = f"{src}/{owner}/{repo}/{version}"
    return {
        "project": proj.project_summary(project_path),
        "runs": proj.list_specific_runs(project_path),
    }


@app.get("/api/projects/{src}/{owner}/{repo}/{version}/source")
def project_source_file(
    src: str,
    owner: str,
    repo: str,
    version: str,
    path: str,
) -> dict[str, Any]:
    try:
        return proj.read_source_file(f"{src}/{owner}/{repo}/{version}", path)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


# --------- 产物文件 ---------


def _err(exc: Exception) -> HTTPException:
    if isinstance(exc, FileNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, FileExistsError):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail=str(exc))


@app.get("/api/artifacts/json")
def artifacts_json(
    project_path: str,
    filename: str,
    run_id: str | None = Query(default=None),
) -> dict[str, Any]:
    try:
        return art.read_full_json(project_path, filename, run_id)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/artifacts/audit")
def artifacts_audit(
    project_path: str,
    run_id: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=0, le=500),
    severity: str | None = Query(default=None),
    verdict: str | None = Query(default=None),
    keyword: str | None = Query(default=None),
) -> dict[str, Any]:
    try:
        return art.read_audit_agent(
            project_path,
            run_id,
            offset=offset,
            limit=limit,
            severity=severity,
            verdict=verdict,
            keyword=keyword,
        )
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/artifacts/audit/{chain_id}")
def artifacts_audit_finding(
    chain_id: str,
    project_path: str,
    run_id: str | None = Query(default=None),
) -> dict[str, Any]:
    try:
        return art.get_finding(project_path, chain_id, run_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"chain not found: {exc}") from exc
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/artifacts/jsonl")
def artifacts_jsonl(
    project_path: str,
    filename: str,
    run_id: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=0, le=1000),
) -> dict[str, Any]:
    try:
        return art.read_jsonl(project_path, filename, run_id, offset=offset, limit=limit)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/artifacts/markdown")
def artifacts_markdown(
    project_path: str,
    filename: str,
    run_id: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=30, ge=0, le=300),
    keyword: str | None = Query(default=None),
) -> dict[str, Any]:
    try:
        return art.read_markdown(
            project_path,
            filename,
            run_id,
            offset=offset,
            limit=limit,
            keyword=keyword,
        )
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


# --------- 日志 ---------


@app.get("/api/logs")
def logs_index() -> dict[str, Any]:
    return {"items": art.list_logs_index()}


@app.get("/api/logs/{name}")
def logs_rounds(
    name: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=30, ge=0, le=200),
    agent: str | None = Query(default=None),
) -> dict[str, Any]:
    try:
        return art.read_logs_rounds(name, offset=offset, limit=limit, agent=agent)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


# --------- 内容浏览：prompts / skills / sinks ---------


class ContentWritePayload(BaseModel):
    content: str
    reason: str = ""


@app.get("/api/prompts")
def prompts_list() -> dict[str, Any]:
    return {"items": cnt.list_prompts()}


@app.get("/api/prompts/{name}")
def prompts_read(name: str) -> dict[str, Any]:
    try:
        return cnt.read_prompt(name)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.put("/api/prompts/{name}")
def prompts_write(name: str, payload: ContentWritePayload) -> dict[str, Any]:
    try:
        return cnt.write_prompt(name, payload.content, reason=payload.reason)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/prompts/{name}/history")
def prompts_history(name: str) -> dict[str, Any]:
    try:
        return {"items": cnt.list_prompt_history(name)}
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/prompts/{name}/history/{version}")
def prompts_history_read(name: str, version: int) -> dict[str, Any]:
    try:
        return cnt.read_prompt_version(name, version)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/skills")
def skills_list() -> dict[str, Any]:
    return {"groups": cnt.list_skill_languages()}


@app.get("/api/skills/{language}/{name}")
def skills_read(language: str, name: str) -> dict[str, Any]:
    try:
        return cnt.read_skill(language, name)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.put("/api/skills/{language}/{name}")
def skills_write(language: str, name: str, payload: ContentWritePayload) -> dict[str, Any]:
    try:
        return cnt.write_skill(language, name, payload.content, reason=payload.reason)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/skills/{language}/{name}/history")
def skills_history(language: str, name: str) -> dict[str, Any]:
    try:
        return {"items": cnt.list_skill_history(language, name)}
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/skills/{language}/{name}/history/{version}")
def skills_history_read(language: str, name: str, version: int) -> dict[str, Any]:
    try:
        return cnt.read_skill_version(language, name, version)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/sinks")
def sinks_list() -> dict[str, Any]:
    return {"groups": cnt.list_sink_languages()}


@app.get("/api/sinks/{language}/{name}")
def sinks_read(language: str, name: str) -> dict[str, Any]:
    try:
        return cnt.read_sink(language, name)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.put("/api/sinks/{language}/{name}")
def sinks_write(language: str, name: str, payload: ContentWritePayload) -> dict[str, Any]:
    try:
        return cnt.write_sink(language, name, payload.content, reason=payload.reason)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


class SinkRulesPayload(BaseModel):
    vulnerability: str
    rules: list[dict[str, Any]]
    reason: str = ""


@app.put("/api/sinks/{language}/{name}/rules")
def sinks_write_rules(
    language: str,
    name: str,
    payload: SinkRulesPayload,
) -> dict[str, Any]:
    try:
        return cnt.write_sink_rules(
            language,
            name,
            vulnerability=payload.vulnerability,
            rules=payload.rules,
            reason=payload.reason,
        )
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/sinks/{language}/{name}/history")
def sinks_history(language: str, name: str) -> dict[str, Any]:
    try:
        return {"items": cnt.list_sink_history(language, name)}
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/sinks/{language}/{name}/history/{version}")
def sinks_history_read(language: str, name: str, version: int) -> dict[str, Any]:
    try:
        return cnt.read_sink_version(language, name, version)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


# --------- 可观测性：仪表盘 / 工作流 / 对话流 ---------


@app.get("/api/dashboard")
def dashboard(refresh: bool = Query(default=False)) -> dict[str, Any]:
    return obs.dashboard_overview(refresh=refresh)


@app.get("/api/workflow")
def workflow_graph(
    project_path: str,
    run_id: str | None = Query(default=None),
) -> dict[str, Any]:
    try:
        return obs.build_workflow_graph(project_path, run_id)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/events")
def events_stream(
    project_path: str,
    run_id: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=500, ge=0, le=5000),
) -> dict[str, Any]:
    try:
        return obs.read_events(project_path, run_id, offset=offset, limit=limit)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/conversations")
def conversations_index(
    project_path: str,
    run_id: str | None = Query(default=None),
) -> dict[str, Any]:
    try:
        return obs.list_conversations(project_path, run_id)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/conversations/{agent}/{turn}")
def conversation_turn(
    agent: str,
    turn: int,
    project_path: str,
    run_id: str | None = Query(default=None),
) -> dict[str, Any]:
    try:
        return obs.read_conversation_turn(project_path, run_id, agent, turn)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/conversations/by-chain")
def conversation_by_chain(
    project_path: str,
    chain_id: str,
    run_id: str | None = Query(default=None),
    agent: str = Query(default="auditor"),
) -> dict[str, Any]:
    try:
        return obs.find_conversation_by_chain(
            project_path, run_id, chain_id, agent=agent
        )
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


# --------- 扫描 / 标注 ---------


class ScanOptionsPayload(BaseModel):
    callscan_use_llm: bool | None = None
    callscan_concurrency: int | None = None
    auditor_concurrency: int | None = None


class CreateScanPayload(BaseModel):
    project_path: str
    name: str = ""
    target_mode: str = "all"  # all | directory
    target_rel_dir: str | None = None
    agents: list[str] = ["treescan", "callscan", "dataflowscan", "auditor"]
    callscan_use_llm: bool | None = None


class UpdateScanPayload(BaseModel):
    name: str | None = None
    agents: list[str] | None = None
    target: dict[str, Any] | None = None
    ground_truth: dict[str, Any] | None = None
    options: ScanOptionsPayload | dict[str, Any] | None = None


class StartScanPayload(BaseModel):
    project_path: str
    scan_id: str
    agents: list[str] | None = None
    resume: bool = False


class RetryAuditFailuresPayload(BaseModel):
    project_path: str


class ScheduleScanPayload(BaseModel):
    project_path: str
    scan_id: str
    scheduled_at: str | None  # ISO 时间字符串；传 null 表示取消
    agents: list[str] | None = None


class MarkPayload(BaseModel):
    project_path: str
    scan_id: str
    chain_id: str
    reviewer: str = "manual"  # codex | manual | cc
    verdict: str | None = None
    review: str | None = None
    user_verdict: str | None = None  # 可选；不传则保留原值
    note: str | None = None  # 可选；不传则保留原值
    favorite: bool | None = None


@app.get("/api/scans")
def scans_list(project_path: str) -> dict[str, Any]:
    try:
        return {"items": scans_mod.list_scans(project_path)}
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.post("/api/scans")
def scans_create(payload: CreateScanPayload) -> dict[str, Any]:
    try:
        return scans_mod.create_scan(
            payload.project_path,
            name=payload.name,
            target_mode=payload.target_mode,
            target_rel_dir=payload.target_rel_dir,
            agents=payload.agents,
            callscan_use_llm=payload.callscan_use_llm,
        )
    except (FileNotFoundError, ValueError, NotADirectoryError) as exc:
        raise _err(exc) from exc


@app.get("/api/scans/{scan_id}")
def scans_get(scan_id: str, project_path: str) -> dict[str, Any]:
    try:
        return scans_mod.get_scan(project_path, scan_id)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.patch("/api/scans/{scan_id}")
def scans_update(scan_id: str, project_path: str, payload: UpdateScanPayload) -> dict[str, Any]:
    try:
        raw = payload.model_dump(exclude_unset=True)
        fields: dict[str, Any] = {}
        for k, v in raw.items():
            if k == "options":
                if v is not None:
                    fields["options"] = v
            elif v is not None:
                fields[k] = v
        return scans_mod.update_scan(project_path, scan_id, fields)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.delete("/api/scans/{scan_id}")
def scans_delete(scan_id: str, project_path: str) -> dict[str, Any]:
    try:
        meta = scans_mod.get_scan(project_path, scan_id)
        stopped = False
        rid = meta.get("last_run_id")
        if meta.get("status") == "running" and rid:
            stopped = run_mod.kill_run(rid)
        scans_mod.delete_scan(project_path, scan_id)
        return {"ok": True, "scan_id": scan_id, "stopped": stopped}
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


def _launch_scan_run(
    project_path: str,
    scan_id: str,
    agents: list[str],
    *,
    resume: bool,
) -> dict[str, Any]:
    """启动扫描子进程，并立即把 scan.json 标为 running（避免前端状态滞后）。"""
    unsupported = [agent for agent in agents if agent not in scans_mod.ALL_AGENTS]
    if unsupported:
        raise ValueError(
            "不支持的扫描 Agent: "
            + ", ".join(unsupported)
            + f"；可选值: {', '.join(scans_mod.ALL_AGENTS)}"
        )
    scans_mod.update_scan_status(
        project_path,
        scan_id,
        scheduled_at=None,
        status="running",
        current_agent=None,
        started_at=None,
        finished_at=None,
        duration_seconds=None,
        last_error=None,
    )
    state = run_mod.start_run(
        "scan",
        {
            "project_path": project_path,
            "scan_id": scan_id,
            "agents": agents,
            "resume": resume,
        },
    )
    scans_mod.update_scan_status(
        project_path,
        scan_id,
        last_run_id=state.run_id,
        status="running",
    )
    return {
        "run_id": state.run_id,
        "scan_id": scan_id,
        "agents": agents,
        "status": "running",
        "resume": resume,
    }


@app.post("/api/scans/{scan_id}/start")
def scans_start(scan_id: str, payload: StartScanPayload) -> dict[str, Any]:
    try:
        meta = scans_mod.get_scan(payload.project_path, scan_id)
        if scans_mod.is_legacy(scan_id):
            raise ValueError("旧扫描记录不可重新执行")
        agents = payload.agents or meta.get("agents") or scans_mod.ALL_AGENTS
        if not agents:
            raise ValueError("必须选择至少一个 Agent")
        if payload.agents:
            scans_mod.update_scan(payload.project_path, scan_id, {"agents": agents})
        return _launch_scan_run(
            payload.project_path,
            scan_id,
            agents,
            resume=bool(payload.resume),
        )
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.post("/api/scans/{scan_id}/retry-audit-failures")
def scans_retry_audit_failures(
    scan_id: str, payload: RetryAuditFailuresPayload
) -> dict[str, Any]:
    """仅重跑 Auditor 中 audit_failures.jsonl 记录的失败链（保留已成功断点）。"""
    try:
        prep = scans_mod.prepare_retry_audit_failures(payload.project_path, scan_id)
        agents = prep["agents"]
        out = _launch_scan_run(
            payload.project_path,
            scan_id,
            agents,
            resume=True,
        )
        out["failure_count"] = prep["failure_count"]
        return out
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.post("/api/scans/{scan_id}/stop")
def scans_stop(scan_id: str, project_path: str) -> dict[str, Any]:
    """主动停止：找到当前 last_run_id 对应的子进程并 terminate。"""
    try:
        meta = scans_mod.get_scan(project_path, scan_id)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc
    rid = meta.get("last_run_id")
    ok = False
    if rid:
        ok = run_mod.kill_run(rid)
    # 即使子进程已经不在了，也确保状态切到 stopped
    scans_mod.update_scan_status(
        project_path,
        scan_id,
        status="stopped",
        current_agent=None,
    )
    return {"ok": ok, "scan_id": scan_id}


@app.post("/api/scans/{scan_id}/schedule")
def scans_schedule(scan_id: str, payload: ScheduleScanPayload) -> dict[str, Any]:
    """设置或取消定时执行（scheduled_at=None 取消）。"""
    try:
        if scans_mod.is_legacy(scan_id):
            raise ValueError("旧扫描记录不可调度")
        # 校验时间格式
        sched_iso: str | None = None
        if payload.scheduled_at:
            from datetime import datetime as _dt

            try:
                target = _dt.fromisoformat(payload.scheduled_at)
            except ValueError as err:
                raise ValueError(f"scheduled_at 时间格式错误: {err}") from err
            if target.tzinfo is None:
                target = target.astimezone()
            sched_iso = target.isoformat(timespec="seconds")
        if payload.agents:
            scans_mod.update_scan(payload.project_path, scan_id, {"agents": payload.agents})
        scans_mod.update_scan_status(
            payload.project_path,
            scan_id,
            scheduled_at=sched_iso,
            status="pending" if sched_iso else None,
        )
        return scans_mod.get_scan(payload.project_path, scan_id)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.get("/api/scans/{scan_id}/console")
def scans_console(
    scan_id: str,
    project_path: str,
    tail: int = Query(default=2000, ge=0, le=20000),
) -> dict[str, Any]:
    """读取该扫描持久化的控制台输出（console.log）。"""
    try:
        scan_dir = scans_mod._scan_dir(project_path, scan_id)
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc
    log_path = scan_dir / "console.log"
    if not log_path.is_file():
        return {"path": str(log_path), "size": 0, "lines": []}
    text = log_path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    if tail and len(lines) > tail:
        lines = lines[-tail:]
    return {
        "path": str(log_path),
        "size": log_path.stat().st_size,
        "mtime": log_path.stat().st_mtime,
        "lines": lines,
    }


@app.get("/api/queue")
def queue_index() -> dict[str, Any]:
    """任务队列：所有 scan 元信息 + 当前 runner 状态。"""
    items = scans_mod.list_all_scans()
    return {"items": items}


@app.get("/api/scans/{scan_id}/marks")
def marks_list(scan_id: str, project_path: str) -> dict[str, Any]:
    try:
        return {"items": scans_mod.list_marks(project_path, scan_id)}
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


@app.post("/api/scans/{scan_id}/marks")
def marks_upsert(scan_id: str, payload: MarkPayload) -> dict[str, Any]:
    try:
        marks = scans_mod.upsert_mark(
            payload.project_path,
            scan_id,
            payload.chain_id,
            reviewer=payload.reviewer,
            verdict=payload.verdict,
            review=payload.review,
            user_verdict=payload.user_verdict,
            note=payload.note,
            favorite=payload.favorite,
        )
        return {"items": marks}
    except (FileNotFoundError, ValueError) as exc:
        raise _err(exc) from exc


# --------- 命令执行 ---------


class PipelinePayload(BaseModel):
    project_path: str
    step: str | None = None  # all / treescan / callscan / dataflowscan / auditor


class SpecificInitPayload(BaseModel):
    project_path: str
    target_rel_dir: str


class AgentStepPayload(BaseModel):
    project_path: str
    agent: str  # treescan / callscan / auditor / ...
    run_id: str | None = None


@app.post("/api/run/pipeline")
def run_pipeline(payload: PipelinePayload) -> dict[str, Any]:
    state = run_mod.start_run("pipeline", payload.model_dump())
    return {"run_id": state.run_id, "cmd": state.cmd, "status": state.status}


@app.post("/api/run/specific")
def run_specific_init(payload: SpecificInitPayload) -> dict[str, Any]:
    state = run_mod.start_run("specific_init", payload.model_dump())
    return {"run_id": state.run_id, "cmd": state.cmd, "status": state.status}


@app.post("/api/run/agent")
def run_agent_step(payload: AgentStepPayload) -> dict[str, Any]:
    state = run_mod.start_run("agent_step", payload.model_dump())
    return {"run_id": state.run_id, "cmd": state.cmd, "status": state.status}


@app.get("/api/run")
def runs_index() -> dict[str, Any]:
    return {"items": run_mod.list_runs()}


@app.get("/api/run/{run_id}/stream")
async def run_stream(run_id: str) -> StreamingResponse:
    state = run_mod.get_run(run_id)
    if state is None:
        raise HTTPException(status_code=404, detail="run not found")
    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    return StreamingResponse(run_mod.stream_run(run_id), media_type="text/event-stream", headers=headers)


@app.get("/api/run/{run_id}")
def run_detail(run_id: str) -> dict[str, Any]:
    state = run_mod.get_run(run_id)
    if state is None:
        raise HTTPException(status_code=404, detail="run not found")
    return {
        "run_id": state.run_id,
        "cmd": state.cmd,
        "status": state.status,
        "return_code": state.return_code,
        "started_at": state.started_at,
        "finished_at": state.finished_at,
        "lines": state.output_lines,
        "detected_run_id": state.detected_run_id,
        "detected_target_rel_dir": state.detected_target_rel_dir,
        "detected_artifacts_dir": state.detected_artifacts_dir,
    }


@app.delete("/api/run/{run_id}")
def run_kill(run_id: str) -> dict[str, Any]:
    ok = run_mod.kill_run(run_id)
    return {"ok": ok}

import { useEffect, useState } from "react";
import { ProjectItem, readArtifactJson } from "../api";
import "../styles/tree.css";

interface Props {
  project: ProjectItem;
  runId: string | null;
}

interface TreeNode {
  files?: string[];
  dirs?: Record<string, TreeNode>;
  binary?: { total: number; by_ext: Record<string, number> };
}

interface State {
  loading: boolean;
  data: TreeNode | null;
  error: string | null;
  meta: { size: number; mtime: number; path: string } | null;
}

export function TreeView({ project, runId }: Props) {
  const [state, setState] = useState<State>({
    loading: true,
    data: null,
    error: null,
    meta: null,
  });

  useEffect(() => {
    setState({ loading: true, data: null, error: null, meta: null });
    readArtifactJson<TreeNode>(project.project_path, "tree.json", runId)
      .then((r) =>
        setState({
          loading: false,
          data: r.data,
          error: null,
          meta: { size: r.size, mtime: r.mtime, path: r.path },
        })
      )
      .catch((err) =>
        setState({ loading: false, data: null, error: String(err), meta: null })
      );
  }, [project.project_path, runId]);

  if (state.loading) return <div className="dm-empty">读取 tree.json…</div>;
  if (state.error)
    return (
      <div className="dm-empty">
        <div className="dm-empty-title">无法读取 tree.json</div>
        <div className="dm-empty-tip">{state.error}</div>
      </div>
    );
  if (!state.data) return null;

  return (
    <>
      <div className="dm-card dm-card-tree">
        <h3 className="dm-card-title">目录树 (tree.json)</h3>
        <div className="dm-meta-line">
          {state.meta?.path} · {Math.round((state.meta?.size ?? 0) / 1024)} KB
        </div>
      </div>
      <div className="dm-card dm-tree-card">
        <TreeRenderer name={project.repo} node={state.data} depth={0} initialOpen />
      </div>
    </>
  );
}

interface NodeProps {
  name: string;
  node: TreeNode;
  depth: number;
  initialOpen?: boolean;
}

function TreeRenderer({ name, node, depth, initialOpen }: NodeProps) {
  const [open, setOpen] = useState<boolean>(initialOpen ?? depth < 1);
  const dirEntries = Object.entries(node.dirs ?? {});
  const files = node.files ?? [];
  const binary = node.binary;

  return (
    <div style={{ paddingLeft: depth === 0 ? 0 : 14 }}>
      <button className="dm-tree-folder" onClick={() => setOpen(!open)}>
        <span className={`dm-tree-caret ${open ? "open" : ""}`}>▸</span>
        <span className="dm-tree-folder-name">{name}/</span>
        <span className="dm-tree-meta">
          {dirEntries.length > 0 && `${dirEntries.length} dirs`}
          {dirEntries.length > 0 && files.length > 0 && " · "}
          {files.length > 0 && `${files.length} files`}
          {binary && ` · ${binary.total} binaries`}
        </span>
      </button>
      {open && (
        <div className="dm-tree-children">
          {dirEntries.map(([k, v]) => (
            <TreeRenderer key={k} name={k} node={v} depth={depth + 1} />
          ))}
          {files.length > 0 && <FileGrid files={files} />}
          {binary && (
            <div className="dm-tree-binary">
              [binary] total={binary.total}
              {Object.entries(binary.by_ext).map(([ext, n]) => (
                <span key={ext} className="dm-tree-ext">
                  {ext}×{n}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function FileGrid({ files }: { files: string[] }) {
  const [shown, setShown] = useState(Math.min(files.length, 200));
  return (
    <div className="dm-tree-files">
      {files.slice(0, shown).map((f) => (
        <span key={f} className="dm-tree-file" title={f}>
          {f}
        </span>
      ))}
      {shown < files.length && (
        <button
          className="dm-btn dm-btn-ghost"
          style={{ fontSize: 11, padding: "2px 8px" }}
          onClick={() => setShown((s) => Math.min(s + 200, files.length))}
        >
          展开剩余 {files.length - shown} 个
        </button>
      )}
    </div>
  );
}

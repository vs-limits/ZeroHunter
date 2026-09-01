import { useMemo } from "react";
import { marked } from "marked";
import DOMPurify from "dompurify";

marked.setOptions({
  breaks: false,
  gfm: true,
});

// 配置 DOMPurify：允许 markdown 常见元素，禁止 script/iframe/event handler 等。
// audit_findings.md 里的 PoC 字段经常包含 <script>alert(1)</script> 这类原文，
// 不做 sanitize 浏览器会真的执行它。
const PURIFY_CONFIG = {
  USE_PROFILES: { html: true },
  FORBID_TAGS: ["style", "script", "iframe", "object", "embed", "form", "input"],
  FORBID_ATTR: ["style", "onerror", "onload", "onclick", "onmouseover"],
} as const;

interface Props {
  source: string;
}

export function Markdown({ source }: Props) {
  const html = useMemo(() => {
    const raw = marked.parse(source) as string;
    return DOMPurify.sanitize(raw, PURIFY_CONFIG as any) as unknown as string;
  }, [source]);
  return <div className="dm-md-body" dangerouslySetInnerHTML={{ __html: html }} />;
}

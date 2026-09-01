import { useEffect, useRef } from "react";

/**
 * 当 dirty=true 时：
 *   1. 拦截浏览器关闭/刷新（beforeunload）
 *   2. 提供 confirmLeave()，在切换路由 / Selection 之前调用
 */
export function useDirtyGuard(dirty: boolean, message: string = "有未保存的修改，确定离开吗？") {
  const ref = useRef(dirty);
  ref.current = dirty;

  useEffect(() => {
    function handler(e: BeforeUnloadEvent) {
      if (!ref.current) return;
      e.preventDefault();
      e.returnValue = message;
    }
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [message]);

  function confirmLeave(): boolean {
    if (!ref.current) return true;
    return window.confirm(message);
  }

  return { confirmLeave };
}

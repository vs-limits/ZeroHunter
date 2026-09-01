import type { LucideIcon } from "lucide-react";

interface Props {
  icon: LucideIcon;
  className?: string;
  size?: number;
}

/** 侧栏 / 导航条统一小图标容器 */
export function NavIcon({ icon: Icon, className = "dm-nav-icon", size = 14 }: Props) {
  return (
    <span className={className} aria-hidden>
      <Icon size={size} strokeWidth={2} />
    </span>
  );
}

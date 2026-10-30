---
name: EnvScope
description: 面向 Windows 与 macOS 的黑白极简环境检查桌面工具。
colors:
  paper: "#fff"
  rail: "#f5f6f4"
  ink: "#202322"
  muted: "#626763"
  line: "#dde1dc"
  selected: "#e5e9e3"
  panel: "#f7f9f5"
  expanded: "#fafbf9"
  primary-hover: "#394038"
  danger: "#ad3030"
  manual-danger: "#a92828"
typography:
  headline:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei UI", sans-serif'
    fontSize: "24px"
    fontWeight: 650
    lineHeight: 1.4
    letterSpacing: "-0.5px"
  title: {fontSize: "16px", fontWeight: 600, lineHeight: 1.5}
  body:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei UI", sans-serif'
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.65
  label: {fontSize: "13px", fontWeight: 400, lineHeight: 1.45}
  field: {fontSize: "13px", fontWeight: 400, lineHeight: 1.5}
  note: {fontSize: "12.5px", fontWeight: 400, lineHeight: 1.75}
  link: {fontSize: "12px", fontWeight: 400, lineHeight: 1.55}
  mono: {fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace", fontSize: "12px", lineHeight: 1.8}
rounded:
  control: "7px"
  link: "2px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  panel: "20px"
  xl: "24px"
  desktop-compact: "28px"
  section: "32px"
  desktop: "40px"
components:
  button-primary: {backgroundColor: "{colors.ink}", textColor: "{colors.paper}", typography: "{typography.label}", rounded: "{rounded.control}", padding: "10px 22px"}
  button-primary-hover: {backgroundColor: "{colors.primary-hover}", textColor: "{colors.paper}"}
  button-secondary: {backgroundColor: "{colors.paper}", textColor: "{colors.ink}", typography: "{typography.label}", rounded: "{rounded.control}", padding: "8px 14px"}
  button-link: {backgroundColor: "transparent", textColor: "{colors.ink}", typography: "{typography.link}", rounded: "{rounded.link}", padding: "2px 0"}
  input: {backgroundColor: "{colors.paper}", textColor: "{colors.ink}", typography: "{typography.field}", rounded: "{rounded.control}", padding: "9px 11px"}
  navigation: {backgroundColor: "transparent", textColor: "{colors.muted}", typography: "{typography.field}", rounded: "{rounded.control}", padding: "10px 12px"}
  navigation-current: {backgroundColor: "{colors.selected}", textColor: "{colors.ink}"}
  summary-panel: {backgroundColor: "{colors.panel}", textColor: "{colors.ink}", rounded: "{rounded.control}", padding: "18px 20px"}
  inspection-row: {backgroundColor: "transparent", textColor: "{colors.ink}", padding: "13px 12px"}
  inspection-row-open: {backgroundColor: "{colors.expanded}", padding: "13px 12px 20px"}
  problem-row: {backgroundColor: "transparent", textColor: "{colors.ink}", padding: "18px 0"}
---

# Design System: EnvScope

## Overview

**Creative North Star: "黑白极简桌面工具"**

面向 Windows 与 macOS 的日常操作界面。文字、细分隔线和少量浅色容器建立层级；检查、修复与守护沿同一操作流程展开，技术证据按需查看。

**Key Characteristics:**

- 固定窄侧栏与单一主内容区。
- 系统字体、可见操作文字和原创线条图标。
- 中性色为主，红色提示需要处理的故障或手动步骤。
- 桌面布局，不做手机适配。

来源：`envscope/web/minimal.css`，随后由 `workspace.css` 覆盖；页面整理见 `workspace_ui.mjs`，图标见 `icons.mjs`。记录以当前实际级联为准。

## Colors

### Primary

`ink` 用于正文、实心主按钮和焦点；主按钮反白。`danger` 用于手动说明、检查错误和检查状态。当前手动问题徽标及检查行左边线仍使用 `manual-danger`，两者均为现有实现。

### Neutral

`paper` 是主画布，`rail` 是侧栏与筛选区，`panel` 用于目标与守护摘要，`expanded` 用于展开行。`line` 分隔内容，`selected` 标识当前导航，`muted` 承载补充说明。状态始终保留文字，不仅依靠颜色。

## Typography

平台系统无衬线字体覆盖中文与英文；原始证据使用等宽字体。页面标题用 `headline`，常规分节用 `title`，正文用 `body`，辅助说明用 `note`。较小的状态与版本文字使用（11–12px），结果摘要标题使用（18px）。主按钮字重（550），当前导航字重（600）；其余角色沿用系统字体。说明通常限制为（78–80ch），表格与运行状态使用等宽数字。

## Layout

左侧栏固定，宽（204px）；主区留白为（26px 40px 48px），内容最大宽（1024px）。主要入口为检测与修复、持续守护、账号资料；其余功能在侧栏内展开，帮助与结束本地服务位于底部。

窗口不超过（1100px）时，侧栏收至（184px），主区留白变为（24px 28px 40px）。最小页面宽（960px），不设置手机断点；视觉检查覆盖（1024、1280、1440px）。常规表单为两列，检查筛选区为三列，操作行可换行。

主流程展示目标摘要、问题、修复方案与守护区。当前流程进度条隐藏；详细检查、证据与高级维护使用原生展开控件。间距采用 frontmatter 中的常用步长，局部内边距以组件记录为准。

## Elevation & Depth

不使用阴影。浅色填充、细边线和留白区分层级；展开行使用浅底。固定侧栏和检查工具栏通过位置保持可用，不添加浮起效果。

## Shapes

控件与摘要容器使用 `control` 圆角，问题与检查列表保持直边分隔。边线通常为（1px）；手动检查行有（3px）红色左边线。图标为（24）单位网格、（1.7px）圆头描边，常规显示（19px），底部操作显示（16px），始终配可见文字。应用标记使用独立的（64）单位取景框图形。

## Components

- **按钮：** 主按钮深底白字，普通按钮白底细边，文本操作带下划线。普通按钮最小高（36px），主按钮最小高（40px）。一键检测保留扫描图形、最小宽（140px）及具体忙碌文字；禁用状态降低透明度，防止重复操作。
- **输入框：** 白底细边，文字框与选择框最小高（40px），复选框保留原生语义。键盘焦点为正文色（2px）外框，偏移（3px）；输入框聚焦时边线加深。
- **导航：** 图标与名称水平排列，行最小高（42px），当前页面浅底加粗。切页保留滚动位置并聚焦标题；“更多功能”可用 Escape 收起。
- **摘要容器：** 目标与守护摘要使用浅底细边，信息输出框为白底；工具分区使用横线分隔。
- **检查列表：** 左侧选择框，中间名称与说明，右侧状态与展开文字。展开显示依据和操作；刷新保留选择、展开状态与焦点。批量工具栏保持可见。
- **问题与方案：** 摘要列出名称、观察与处理状态，原因按需展开。修复先展示影响与改动，再确认；结果与证据归入同一流程。

按钮仅对背景色和边框色做（120ms）过渡，不使用进入动画；减少动态效果设置关闭过渡与动画。

## Do's and Don'ts

### Do

- Do 保留可见文字、明确状态、键盘焦点与原生表单语义。
- Do 把完整检查与技术证据放在可展开区域，保留访问路径。
- Do 在 1024、1280、1440px 桌面宽度核对布局。

### Don't

- Don't 引入手机布局、营销首页、大量装饰卡片、渐变、发光或 emoji。
- Don't 用颜色、图标或“通过”文案掩盖未测、未实现或权限不足。
- Don't 把静态预览或视觉状态当作检测与修复已完成的证据。

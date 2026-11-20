defmodule CredentialBreachWeb.AuditComponents do
  @moduledoc """
  调查台专用展示组件：严重级别徽章、阶段标识、统计卡、分类标签等。
  全部基于 Tailwind 与 daisyUI 主题令牌，明/暗主题自适应。
  """
  use Phoenix.Component

  alias CredentialBreach.Audit.Meta

  @doc "严重级别小芯片。"
  attr :severity, :atom, required: true, values: [:critical, :high, :medium, :low, :info]
  attr :class, :string, default: ""

  def severity_chip(assigns) do
    meta = Meta.severity(assigns.severity)
    assigns = assign(assigns, :meta, meta)

    ~H"""
    <span class={[
      "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold whitespace-nowrap",
      @meta.chip,
      @class
    ]}>
      <span
        :if={@severity in [:critical, :high]}
        class="size-1.5 rounded-full bg-current animate-pulse"
      ></span>
      {@meta.name}
    </span>
    """
  end

  @doc "事件类别徽章。"
  attr :category, :atom, required: true
  attr :class, :string, default: ""

  def category_badge(assigns) do
    meta = Meta.category(assigns.category)
    assigns = assign(assigns, :meta, meta)

    ~H"""
    <span class={["badge badge-sm gap-1 py-2.5 font-medium", @meta.badge, @class]}>{@meta.name}</span>
    """
  end

  @doc "攻击阶段徽章（带数字）。"
  attr :stage, :integer, required: true
  attr :class, :string, default: ""

  def stage_badge(assigns) do
    meta = Meta.stage(assigns.stage)
    assigns = assign(assigns, :meta, meta)

    ~H"""
    <span class={["badge badge-sm gap-1.5 font-semibold", @meta.badge, @class]}>
      <span class="grid size-4 place-items-center rounded-full bg-current/20 text-[10px]">{@stage}</span>
      {@meta.name}
    </span>
    """
  end

  @doc "统计卡片。"
  attr :label, :string, required: true
  attr :value, :any, default: nil
  attr :hint, :string, default: nil
  attr :tone, :string, default: "default", values: ~w(default danger warning info success)
  attr :icon, :string, default: nil
  slot :inner_block

  def stat_card(assigns) do
    ~H"""
    <div class={[
      "card border bg-base-100/70 backdrop-blur transition-all duration-200 hover:-translate-y-0.5 hover:shadow-lg",
      tone_border(@tone)
    ]}>
      <div class="card-body p-4 gap-1">
        <div class="flex items-center justify-between gap-2">
          <p class="text-xs font-medium uppercase tracking-wide text-base-content/60">{@label}</p>
          <.icon :if={@icon} name={@icon} class={["size-4 opacity-70", tone_text(@tone)]} />
        </div>
        <p class={["text-2xl font-bold tabular-nums leading-tight", tone_text(@tone)]}>
          {render_slot(@inner_block) || @value}
        </p>
        <p :if={@hint} class="text-xs text-base-content/50">{@hint}</p>
      </div>
    </div>
    """
  end

  @doc "区块容器，带标题与右侧操作槽。"
  attr :id, :string, default: nil
  attr :title, :string, required: true
  attr :subtitle, :string, default: nil
  attr :icon, :string, default: nil
  attr :class, :string, default: ""
  slot :actions
  slot :inner_block, required: true

  def section_panel(assigns) do
    ~H"""
    <section id={@id} class={["card border bg-base-100/80 backdrop-blur overflow-visible", @class]}>
      <header class="flex flex-wrap items-center justify-between gap-3 border-b border-base-300/70 px-5 py-4">
        <div class="flex items-center gap-2.5">
          <.icon :if={@icon} name={@icon} class="size-5 text-primary" />
          <div>
            <h2 class="text-base font-semibold leading-tight">{@title}</h2>
            <p :if={@subtitle} class="text-xs text-base-content/55 mt-0.5">{@subtitle}</p>
          </div>
        </div>
        <div :if={@actions != []} class="flex items-center gap-2">{render_slot(@actions)}</div>
      </header>
      <div class="p-5">
        {render_slot(@inner_block)}
      </div>
    </section>
    """
  end

  @doc "空状态占位。"
  attr :icon, :string, default: "hero-check-circle"
  attr :title, :string, default: "暂无相关记录"
  attr :note, :string, default: nil

  def empty_state(assigns) do
    ~H"""
    <div class="flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-base-300 py-10 text-center">
      <.icon name={@icon} class="size-8 text-success/70" />
      <p class="text-sm font-medium text-base-content/70">{@title}</p>
      <p :if={@note} class="max-w-md text-xs text-base-content/45">{@note}</p>
    </div>
    """
  end

  @doc "敏感数据红色标记。"
  attr :flag, :boolean, default: false
  attr :class, :string, default: ""

  def sensitive_flag(assigns) do
    ~H"""
    <span
      :if={@flag}
      class={[
        "inline-flex items-center gap-1 rounded-md bg-error/15 px-1.5 py-0.5 text-[11px] font-semibold text-error",
        @class
      ]}
    >
      <.icon name="hero-eye-slash-micro" class="size-3.5" /> 敏感
    </span>
    """
  end

  defp tone_border("danger"), do: "border-error/30"
  defp tone_border("warning"), do: "border-warning/30"
  defp tone_border("info"), do: "border-info/30"
  defp tone_border("success"), do: "border-success/30"
  defp tone_border(_), do: "border-base-300/70"

  defp tone_text("danger"), do: "text-error"
  defp tone_text("warning"), do: "text-warning"
  defp tone_text("info"), do: "text-info"
  defp tone_text("success"), do: "text-success"
  defp tone_text(_), do: "text-base-content"

  # 复用核心组件里的 icon
  defp icon(assigns), do: CredentialBreachWeb.CoreComponents.icon(assigns)
end

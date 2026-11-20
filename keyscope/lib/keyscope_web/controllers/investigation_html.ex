defmodule KeyscopeWeb.InvestigationHTML do
  use KeyscopeWeb, :html

  embed_templates "investigation_html/*"

  @doc "格式化 UTC 时间"
  def fmt_time(nil), do: "—"

  def fmt_time(%DateTime{} = dt) do
    Calendar.strftime(dt, "%m-%d %H:%M:%S")
  end

  def fmt_date(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d")
  def fmt_date(_), do: "—"

  def severity_badge(sev) do
    label =
      case sev do
        :critical -> "严重"
        :high -> "高"
        :medium -> "中"
        :low -> "低"
        _ -> "信息"
      end

    assigns = %{sev: sev, label: label}

    ~H"""
    <span class={["badge", "badge-#{@sev}"]}>{@label}</span>
    """
  end

  def risk_banner({level, text}) do
    assigns = %{level: level, text: text}

    ~H"""
    <div class={["risk-banner", "risk-#{@level}"]}>
      <strong>综合风险评级:</strong> {@text}
    </div>
    """
  end
end

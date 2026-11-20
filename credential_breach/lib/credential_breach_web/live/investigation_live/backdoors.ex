defmodule CredentialBreachWeb.InvestigationLive.Backdoors do
  @moduledoc "账号与后门标签页：新建身份、密钥、提权、网络与跨账号持久化通道。"
  use CredentialBreachWeb, :html

  attr :report, :map, required: true

  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <.stat_card
          label="后门/受影响身份"
          value={length(@report.new_identities.users)}
          icon="hero-users"
          tone="danger"
        />
        <.stat_card
          label="后门角色"
          value={length(@report.new_identities.roles)}
          icon="hero-user-group"
          tone="danger"
        />
        <.stat_card
          label="权限/策略改动"
          value={length(@report.backdoors)}
          icon="hero-lock-closed"
          tone="warning"
        />
        <.stat_card
          label="网络放行规则"
          value={network_rule_count(@report)}
          icon="hero-globe-alt"
          tone="warning"
        />
      </div>

      <.section_panel
        id="new-users"
        title="新建账号与新访问密钥"
        subtitle="攻击者种下的长期身份凭证，吊销原密钥不会使这些失效"
        icon="hero-user-plus"
      >
        <.empty_state
          :if={@report.new_identities.users == []}
          icon="hero-check-circle"
          title="未发现新建 IAM 用户"
        />
        <div :if={@report.new_identities.users != []} class="overflow-x-auto">
          <table class="table table-sm">
            <thead>
              <tr class="text-xs uppercase text-base-content/50">
                <th>IAM 用户名</th>
                <th class="w-24 text-center">新建</th>
                <th>访问密钥</th>
                <th class="w-28 text-center">控制台登录</th>
                <th class="w-24 text-center">管理员</th>
              </tr>
            </thead>
            <tbody>
              <tr
                :for={u <- @report.new_identities.users}
                key={u.user_name}
                class="hover:bg-base-200/50"
              >
                <td class="font-mono text-xs font-semibold">{u.user_name}</td>
                <td class="text-center">
                  <span :if={u.newly_created?} class="badge badge-error badge-sm">新建用户</span>
                  <span :if={!u.newly_created?} class="badge badge-ghost badge-sm">既有用户</span>
                </td>
                <td>
                  <div :for={k <- u.access_keys} class="flex items-center gap-1.5">
                    <.icon name="hero-key" class="size-3.5 text-warning" />
                    <span class="font-mono text-xs">{k}</span>
                  </div>
                </td>
                <td class="text-center">
                  <.icon :if={u.console_login?} name="hero-check-circle" class="size-5 text-error" />
                  <.icon
                    :if={!u.console_login?}
                    name="hero-minus-circle"
                    class="size-5 text-base-content/30"
                  />
                </td>
                <td class="text-center">
                  <.icon :if={u.admin?} name="hero-check-badge" class="size-5 text-error" />
                  <.icon :if={!u.admin?} name="hero-minus-circle" class="size-5 text-base-content/30" />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </.section_panel>

      <.section_panel id="roles" title="后门角色与实例配置" icon="hero-cog-6-tooth">
        <.empty_state
          :if={@report.new_identities.roles == []}
          icon="hero-check-circle"
          title="未发现新建角色"
        />
        <ul :if={@report.new_identities.roles != []} class="space-y-2.5">
          <li
            :for={role <- @report.new_identities.roles}
            key={role.name}
            class="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-error/30 bg-error/5 p-3"
          >
            <div>
              <p class="font-mono text-sm font-semibold">{role.name}</p>
              <p class="text-xs text-base-content/55">{role.kind} · {fmt(role.created_at)}</p>
            </div>
            <span :if={role.open_assume?} class="badge badge-error badge-sm gap-1">
              <.icon name="hero-globe-alt" class="size-3.5" /> 信任策略 Principal=*
            </span>
          </li>
        </ul>
      </.section_panel>

      <.section_panel
        id="policy-backdoors"
        title="权限提升与策略后门"
        icon="hero-lock-closed"
      >
        <.empty_state
          :if={@report.backdoors == []}
          icon="hero-check-circle"
          title="未发现策略类后门"
        />
        <ul :if={@report.backdoors != []} class="space-y-2.5">
          <li
            :for={b <- @report.backdoors}
            key={b.event.event_id}
            class="rounded-lg border border-base-300 p-3 transition-colors hover:border-error/40"
          >
            <div class="flex flex-wrap items-center gap-2">
              <.severity_chip severity={b.event.severity} />
              <span class="badge badge-sm badge-ghost">{b.kind}</span>
              <p class="text-sm font-medium">{b.event.title}</p>
            </div>
            <p class="mt-1.5 text-xs text-base-content/60">{b.detail}</p>
            <p class="mt-1 font-mono text-[11px] text-base-content/45">目标：{b.target}</p>
          </li>
        </ul>
      </.section_panel>

      <.section_panel
        id="network-backdoors"
        title="网络面开放（安全组入站规则）"
        icon="hero-globe-alt"
      >
        <.empty_state
          :if={@report.network_changes == []}
          icon="hero-check-circle"
          title="未发现安全组改动"
        />
        <div :if={@report.network_changes != []} class="space-y-3">
          <div
            :for={nc <- @report.network_changes}
            key={nc.event.event_id}
            class="rounded-lg border border-warning/30 bg-warning/5 p-3"
          >
            <p class="font-mono text-xs font-semibold">{nc.security_group}</p>
            <div class="mt-2 flex flex-wrap gap-2">
              <span
                :for={rule <- nc.rules}
                key={rule.port <> rule.cidr}
                class="badge badge-warning badge-sm gap-1 font-mono"
              >
                端口 {rule.port} ← {rule.cidr}
              </span>
            </div>
          </div>
        </div>
      </.section_panel>
    </div>
    """
  end

  defp network_rule_count(report) do
    report.network_changes |> Enum.map(&length(&1.rules)) |> Enum.sum()
  end

  defp fmt(%DateTime{} = dt), do: Calendar.strftime(dt, "%m-%d %H:%M UTC")
  defp fmt(_), do: "—"
end

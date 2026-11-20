defmodule CredentialBreachWeb.InvestigationLive.Intro do
  @moduledoc "调查台顶部的场景说明与风险横幅。"
  use CredentialBreachWeb, :html

  def render(assigns) do
    ~H"""
    <div class="relative overflow-hidden rounded-2xl border border-error/25 bg-gradient-to-br from-error/10 via-base-100 to-base-100 p-6 sm:p-8">
      <div class="absolute -right-10 -top-10 size-40 rounded-full bg-error/10 blur-2xl"></div>
      <div class="relative flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div class="space-y-2">
          <div class="flex items-center gap-2">
            <span class="inline-flex items-center gap-1.5 rounded-full bg-error/15 px-2.5 py-1 text-xs font-semibold text-error">
              <.icon name="hero-shield-exclamation" class="size-4" /> 凭证泄露应急响应
            </span>
          </div>
          <h1 class="text-2xl font-bold tracking-tight sm:text-3xl">泄露密钥影响面调查台</h1>
          <p class="max-w-2xl text-sm leading-relaxed text-base-content/70">
            导入云操作审计日志（CloudTrail 风格 JSONL），按泄露的访问密钥还原全部调用，
            自动梳理被读取或下载的数据、新建账号与密钥、各类后门改动、被删改的资源，
            并把每一步串成完整的攻击者操作经过。
          </p>
        </div>
        <div class="hidden shrink-0 sm:block">
          <div class="grid size-20 place-items-center rounded-2xl bg-error/10 text-error">
            <.icon name="hero-key" class="size-10" />
          </div>
        </div>
      </div>
    </div>
    """
  end
end

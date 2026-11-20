defmodule CredentialBreachWeb.ImportPanel do
  @moduledoc """
  日志导入与泄露密钥选择面板（LiveComponent）。
  支持三种导入方式：文件上传、内置模拟样例、直接粘贴 JSONL。
  """
  use CredentialBreachWeb, :live_component

  # 上传配置归父 LiveView 所有（allow_upload 在父级调用），这里通过 assign 传入
  attr :uploads_conf, :map, required: true
  attr :dataset, :map, default: nil
  attr :upload_error, :string, default: nil
  attr :access_keys, :list, default: []
  attr :leaked_key, :string, default: ""

  @impl true
  def render(assigns) do
    ~H"""
    <section class="card border bg-base-100/80 backdrop-blur">
      <header class="flex items-center gap-2.5 border-b border-base-300/70 px-5 py-4">
        <.icon name="hero-arrow-up-tray" class="size-5 text-primary" />
        <div class="flex-1">
          <h2 class="text-base font-semibold">1. 导入审计日志</h2>
          <p class="text-xs text-base-content/55 mt-0.5">
            支持 CloudTrail 风格 JSONL，每行一条事件，最大 20MB，仅在本地内存解析
          </p>
        </div>
        <button
          :if={@dataset}
          id="reset-btn"
          type="button"
          phx-click="reset"
          phx-target={@myself}
          class="btn btn-ghost btn-xs border border-base-300"
        >
          <.icon name="hero-arrow-uturn-left" class="size-3.5" /> 重新开始
        </button>
      </header>

      <div class="grid gap-5 p-5 lg:grid-cols-2">
        <div class="space-y-4">
          <form id="upload-form" phx-submit="ingest_upload" phx-change="validate_upload">
            <div
              class="flex flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed border-base-300 bg-base-200/40 px-4 py-8 text-center transition-colors hover:border-primary/50"
              phx-drop-target={@uploads_conf.audit_file.ref}
            >
              <div class="grid size-12 place-items-center rounded-full bg-primary/10 text-primary">
                <.icon name="hero-cloud-arrow-up" class="size-6" />
              </div>
              <div>
                <.live_file_input
                  upload={@uploads_conf.audit_file}
                  class="text-sm file:mr-3 file:rounded-lg file:border-0 file:bg-primary file:px-3 file:py-1.5 file:text-primary-content file:cursor-pointer"
                />
                <p class="mt-2 text-xs text-base-content/50">拖拽 .jsonl / .ndjson / .txt 到此处，或点击选择</p>
              </div>
            </div>

            <div
              :for={entry <- @uploads_conf.audit_file.entries}
              class="mt-3 rounded-lg border border-base-300 p-3"
            >
              <div class="flex items-center justify-between gap-2">
                <p class="truncate text-sm font-medium">{entry.client_name}</p>
                <button
                  type="button"
                  phx-click="cancel_upload"
                  phx-value-ref={entry.ref}
                  class="btn btn-ghost btn-xs btn-circle"
                  aria-label="移除文件"
                >
                  <.icon name="hero-x-mark" class="size-4" />
                </button>
              </div>
              <progress
                max={100}
                value={entry.progress}
                class="progress progress-primary mt-2 h-1.5 w-full"
              ></progress>
              <p
                :for={err <- upload_errors(@uploads_conf.audit_file, entry)}
                class="mt-1 text-xs text-error"
              >
                {error_to_text(err)}
              </p>
            </div>

            <button
              type="submit"
              class="btn btn-primary mt-3 w-full"
              disabled={@uploads_conf.audit_file.entries == []}
            >
              <.icon name="hero-magnifying-glass-circle" class="size-4" /> 上传并解析
            </button>
          </form>

          <div class="divider text-xs text-base-content/40">或者</div>

          <button
            id="load-sample-btn"
            phx-click="load_sample"
            phx-target={@myself}
            class="btn btn-outline btn-primary w-full"
          >
            <.icon name="hero-sparkles" class="size-4" /> 载入内置模拟日志（含完整攻击链）
          </button>
        </div>

        <div class="space-y-4">
          <form phx-submit="ingest_paste" phx-target={@myself} id="paste-form">
            <label class="text-xs font-semibold text-base-content/70">粘贴 JSONL 日志内容</label>
            <textarea
              name="pasted"
              rows={6}
              placeholder='{"eventTime":"...","eventName":"GetObject","userIdentity":{"accessKeyId":"AKIA..."},...}'
              class="textarea textarea-bordered mt-1 w-full font-mono text-xs leading-relaxed"
            ></textarea>
            <button type="submit" class="btn btn-ghost btn-sm mt-2 w-full border border-base-300">
              <.icon name="hero-clipboard-document-check" class="size-4" /> 解析粘贴内容
            </button>
          </form>

          <div :if={@upload_error} class="alert alert-error text-sm py-2">
            <.icon name="hero-exclamation-circle" class="size-4 shrink-0" />
            <span>{@upload_error}</span>
          </div>

          <div :if={@dataset} class="rounded-xl border border-success/30 bg-success/5 p-4">
            <div class="flex items-center gap-2 text-sm font-semibold text-success">
              <.icon name="hero-check-circle" class="size-4" /> 已加载数据集
            </div>
            <dl class="mt-2 space-y-1 text-xs text-base-content/70">
              <div class="flex justify-between gap-2">
                <dt class="text-base-content/50">来源</dt><dd class="truncate font-medium">
                  {@dataset.source_name}
                </dd>
              </div>
              <div class="flex justify-between gap-2">
                <dt class="text-base-content/50">日志行</dt><dd class="font-medium">
                  {@dataset.total_lines}
                </dd>
              </div>
              <div class="flex justify-between gap-2">
                <dt class="text-base-content/50">有效事件</dt><dd class="font-medium">
                  {length(@dataset.events)}
                </dd>
              </div>
              <div :if={@dataset.bad_lines != []} class="flex justify-between gap-2">
                <dt class="text-base-content/50">坏行</dt>
                <dd class="font-medium text-warning">{length(@dataset.bad_lines)} 行已跳过</dd>
              </div>
            </dl>
          </div>
        </div>
      </div>

      <div :if={@access_keys != []} class="border-t border-base-300/70 px-5 py-4">
        <h3 class="flex items-center gap-2 text-sm font-semibold">
          <.icon name="hero-key" class="size-4 text-warning" /> 2. 选择泄露的访问密钥
        </h3>
        <p class="mt-1 text-xs text-base-content/55">数据集中识别到的全部密钥，按调用次数排序；已自动预选最可疑的一把</p>

        <div class="mt-3 grid gap-2 sm:grid-cols-2">
          <button
            :for={{key, count} <- @access_keys}
            id={"key-option-#{key}"}
            key={key}
            type="button"
            phx-click="select_key"
            phx-value-key={key}
            phx-target={@myself}
            class={[
              "flex items-center justify-between gap-2 rounded-lg border px-3 py-2.5 text-left transition-all",
              (@leaked_key == key &&
                 "border-error bg-error/10 ring-1 ring-error/30") ||
                "border-base-300 hover:border-primary/50 hover:bg-base-200/50"
            ]}
          >
            <div class="min-w-0">
              <p class="truncate font-mono text-xs font-semibold">{key}</p>
              <p class="text-[11px] text-base-content/50">{count} 次调用</p>
            </div>
            <.icon
              :if={@leaked_key == key}
              name="hero-check-badge"
              class="size-5 shrink-0 text-error"
            />
          </button>
        </div>
      </div>
    </section>
    """
  end

  @impl true
  def handle_event("load_sample", _params, socket) do
    send(self(), :load_sample)
    {:noreply, socket}
  end

  def handle_event("ingest_paste", params, socket) do
    send(self(), {:ingest_paste, params})
    {:noreply, socket}
  end

  def handle_event("select_key", %{"key" => key}, socket) do
    send(self(), {:select_key, key})
    {:noreply, socket}
  end

  def handle_event("reset", _params, socket) do
    send(self(), :reset_investigation)
    {:noreply, socket}
  end

  defp error_to_text(:too_large), do: "文件超过 20MB 限制"
  defp error_to_text(:too_many_files), do: "一次只能上传一个文件"
  defp error_to_text(:not_accepted), do: "文件类型不被接受，请使用 .jsonl / .ndjson / .txt"
  defp error_to_text(other), do: inspect(other)
end

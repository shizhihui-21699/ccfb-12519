defmodule CredentialBreach.Audit.Meta do
  @moduledoc """
  取证视图用到的展示元数据：攻击阶段、事件类别、严重级别的中文名与配色。
  配色统一走 daisyUI 主题令牌，保证明暗主题都可用。
  """

  @stages %{
    1 => %{
      name: "验证接入",
      short: "接入",
      desc: "攻击者用泄露密钥试探身份与权限边界",
      badge: "badge-info",
      dot: "bg-info",
      ring: "border-info/40"
    },
    2 => %{
      name: "侦察枚举",
      short: "侦察",
      desc: "枚举 IAM、存储、计算与审计配置，绘制攻击面地图",
      badge: "badge-primary",
      dot: "bg-primary",
      ring: "border-primary/40"
    },
    3 => %{
      name: "数据窃取",
      short: "窃取",
      desc: "批量下载对象、导出数据库快照、在日志中翻找凭证",
      badge: "badge-warning",
      dot: "bg-warning",
      ring: "border-warning/40"
    },
    4 => %{
      name: "建立后门",
      short: "后门",
      desc: "新建账号与密钥、提升权限、开放网络与跨账号访问",
      badge: "badge-error",
      dot: "bg-error",
      ring: "border-error/40"
    },
    5 => %{
      name: "压制审计",
      short: "规避",
      desc: "关停、篡改并删除 CloudTrail，掩盖后续行踪",
      badge: "badge-error",
      dot: "bg-error",
      ring: "border-error/40"
    },
    6 => %{
      name: "破坏清除",
      short: "破坏",
      desc: "删除备份与快照、关停实例，削弱恢复与取证能力",
      badge: "badge-error",
      dot: "bg-error",
      ring: "border-error/40"
    },
    7 => %{
      name: "吊销后尝试",
      short: "吊销后",
      desc: "密钥失效后攻击者仍在尝试调用，证明攻击活动未停止",
      badge: "badge-neutral",
      dot: "bg-neutral-content",
      ring: "border-neutral/40"
    }
  }

  @categories %{
    recon: %{name: "侦察枚举", badge: "badge-primary"},
    data_access: %{name: "数据读取/下载", badge: "badge-warning"},
    data_export: %{name: "数据库导出", badge: "badge-warning"},
    credential_harvest: %{name: "凭证翻找", badge: "badge-warning"},
    backdoor_identity: %{name: "后门身份", badge: "badge-error"},
    backdoor_permission: %{name: "权限/策略后门", badge: "badge-error"},
    backdoor_network: %{name: "网络后门", badge: "badge-error"},
    defense_evasion: %{name: "审计规避", badge: "badge-error"},
    destruction: %{name: "破坏/删除", badge: "badge-error"},
    denied: %{name: "被拒/失败调用", badge: "badge-neutral"},
    other: %{name: "其他写操作", badge: "badge-ghost"}
  }

  @severities %{
    critical: %{
      name: "严重",
      order: 4,
      text: "text-error",
      chip: "bg-error/15 text-error border border-error/30"
    },
    high: %{
      name: "高危",
      order: 3,
      text: "text-error/80",
      chip: "bg-error/10 text-error/90 border border-error/20"
    },
    medium: %{
      name: "中危",
      order: 2,
      text: "text-warning",
      chip: "bg-warning/15 text-warning border border-warning/30"
    },
    low: %{
      name: "低危",
      order: 1,
      text: "text-info",
      chip: "bg-info/10 text-info border border-info/20"
    },
    info: %{
      name: "信息",
      order: 0,
      text: "text-base-content/60",
      chip: "bg-base-300/60 text-base-content/70 border border-base-300"
    }
  }

  @ip_labels %{
    "185.220.101.44" => %{
      label: "Tor 出口节点",
      note: "命中公开 Tor 中继地址特征，匿名网络出口，与公司任何办公网/IDC 均不匹配"
    },
    "45.155.204.118" => %{
      label: "境外 VPS（疑似 C2）",
      note: "与被篡改实例 userData 中的回连地址 45.155.204.118:8443 一致"
    },
    "47.91.40.12" => %{
      label: "云厂商 IDC（CI 正常流量）",
      note: "jenkins-runner 的日常构建流量，不属于本次泄露密钥"
    },
    "112.65.88.21" => %{
      label: "上海办公网出口",
      note: "员工 zhang.wei 的日常办公地址"
    }
  }

  def stages, do: @stages
  def stage(n), do: Map.fetch!(@stages, n)
  def categories, do: @categories
  def category(n), do: Map.fetch!(@categories, n)
  def severities, do: @severities
  def severity(n), do: Map.fetch!(@severities, n)
  def ip_labels, do: @ip_labels

  def ip_label(ip),
    do: Map.get(@ip_labels, ip, %{label: "未知来源地址", note: "数据集中无该地址的历史基线，需结合威胁情报进一步确认"})
end

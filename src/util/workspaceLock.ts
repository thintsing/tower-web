// 服务器版只读闸门：服务端离线 / 密钥无效 / 工作区损坏时禁止改内存状态，
// 避免用户以为改动已保存。放在独立模块里，store 与同步层都能引用而不循环依赖。
let readOnly = false

export function isWorkspaceReadOnly(): boolean {
  return readOnly
}

export function setWorkspaceReadOnly(value: boolean): void {
  readOnly = value
}

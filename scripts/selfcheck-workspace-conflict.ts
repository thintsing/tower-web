// 自检：409 冲突不自动合并，草稿保留、来源文案与刷新后恢复规则。
// 用法：npm run selfcheck:workspace-conflict
import assert from 'node:assert/strict'
import {
  CONFLICT_CLEAR_LOCAL_LABEL,
  CONFLICT_KEEP_LOCAL_LABEL,
  CONFLICT_PEER_WINDOW_MS,
  CONFLICT_USE_SERVER_LABEL,
  canClearConflictMarker,
  conflictMessage,
  conflictProbeAction,
  conflictSourceFromPeerWrite,
  conflictSourceText,
  decideConflictResume,
  planServerChoice,
  shouldResumeConflictDraft,
  type ConflictDraft,
} from '../src/workspaceConflict'
import { hasWorkspaceContent, DEFAULT_EXPORT_CONFIG_NAME, DEFAULT_SELECTED_SCHEME_ID } from '../src/workspaceContent'
import { normalizeWorkspaceData } from '../src/workspaceValidation'

let failures = 0

function check(label: string, run: () => void): void {
  try {
    run()
    console.log(`✓ ${label}`)
  } catch (error) {
    failures += 1
    console.error(`✗ ${label}`)
    console.error(`  ${error instanceof Error ? error.message : String(error)}`)
  }
}

const draft: ConflictDraft = {
  signature: 'abc:100',
  source: 'client',
  serverVersion: 7,
  at: 1000,
}

check('同一浏览器另一个标签页最近写过 → 判定为标签页', () => {
  assert.equal(conflictSourceFromPeerWrite(1000, 1000 + 10, CONFLICT_PEER_WINDOW_MS), 'tab')
  assert.match(conflictSourceText('tab'), /另一个标签页/)
})

check('没有同浏览器写入记录或已过期 → 判定为另一个客户端', () => {
  assert.equal(conflictSourceFromPeerWrite(undefined, 1000), 'client')
  assert.equal(conflictSourceFromPeerWrite(1000, 1000 + CONFLICT_PEER_WINDOW_MS + 1), 'client')
  assert.equal(conflictSourceText('client'), '另一个客户端')
  assert.doesNotMatch(conflictSourceText('client'), /另一台设备/)
})

check('冲突文案同时给出两个明确选择', () => {
  const message = conflictMessage('tab')
  assert.match(message, new RegExp(CONFLICT_KEEP_LOCAL_LABEL))
  assert.match(message, new RegExp(CONFLICT_USE_SERVER_LABEL))
  assert.match(message, /本机还有未保存的改动/)
})

check('刷新后只有本机仍有内容才恢复冲突，避免无草稿的幽灵提示', () => {
  assert.equal(shouldResumeConflictDraft(null, true), false)
  assert.equal(shouldResumeConflictDraft(draft, false), false)
  assert.equal(shouldResumeConflictDraft(draft, true), true)
})

check('冲突期间的编辑不会让标记失效（签名变化仍保留草稿）', () => {
  assert.equal(shouldResumeConflictDraft({ ...draft, signature: 'changed:200' }, true), true)
})

check('冲突标记只由记录它的标签页清除，别的标签页不会解掉草稿保护', () => {
  const owned = { ...draft, tabId: 'tab-a' }
  assert.equal(canClearConflictMarker(owned, { tabId: 'tab-b', signature: 'abc:100', hasLocalContent: true }), false)
  assert.equal(canClearConflictMarker(owned, { tabId: 'tab-a', signature: 'abc:100', hasLocalContent: true }), true)
  // 旧标记没有 tabId：内容签名仍一致才允许清除。
  assert.equal(canClearConflictMarker(draft, { tabId: 'tab-b', signature: 'abc:100', hasLocalContent: true }), true)
  assert.equal(canClearConflictMarker(draft, { tabId: 'tab-b', signature: 'changed:200', hasLocalContent: true }), false)
})

check('别的标签页的冲突标记不由本标签页恢复，签名变化提示「又有改动」', () => {
  const owned = { ...draft, tabId: 'tab-a' }
  assert.equal(decideConflictResume(owned, { tabId: 'tab-b', signature: 'abc:100', hasLocalContent: true }), 'foreign')
  assert.equal(decideConflictResume(owned, { tabId: 'tab-a', signature: 'abc:100', hasLocalContent: true }), 'resume')
  assert.equal(decideConflictResume(owned, { tabId: 'tab-a', signature: 'changed:200', hasLocalContent: true }), 'resume-edited')
})

check('冲突 + 断网 + 重连失败后仍会继续排重试，再连上时回到冲突选择', () => {
  // 第一次探测失败 → retry；重试再次失败 → 仍是 retry（链路不断）。
  assert.equal(conflictProbeAction(null, { serverMode: true, state: 'offline' }), 'retry')
  assert.equal(conflictProbeAction(null, { serverMode: true, state: 'conflict' }), 'retry')
  // 密钥无效不空转，保留草稿等用户重新带 key 打开。
  assert.equal(conflictProbeAction(null, { serverMode: true, state: 'unauthorized' }), 'wait-for-key')
  // 再连上拿到版本号 → 继续让用户选择。
  assert.equal(conflictProbeAction(9, { serverMode: true, state: 'offline' }), 'resolved')
  // 服务端已改回 local：不能再把状态写回 server。
  assert.equal(conflictProbeAction(null, { serverMode: false, state: 'local' }), 'left-server-mode')
})

check('服务端版本 0 时「改用服务端」只提示，不反向上传本机草稿', () => {
  assert.equal(planServerChoice(0), 'confirm-empty-server')
  assert.equal(planServerChoice(5), 'fetch-server')
  assert.equal(planServerChoice(null), 'retry')
  assert.match(CONFLICT_CLEAR_LOCAL_LABEL, /清空本机/)
})

check('仅改了当前方案 / 策略选择 / 配置名 / Auth Key 也算本机有内容', () => {
  const empty = normalizeWorkspaceData({})
  assert.equal(hasWorkspaceContent(empty), false)
  assert.equal(hasWorkspaceContent({ ...empty, selectedSchemeID: 'my-custom-scheme' }), true)
  assert.equal(hasWorkspaceContent({ ...empty, policySelections: { 'rule-1': 'proxy' } as never }), true)
  assert.equal(hasWorkspaceContent({ ...empty, exportConfigName: 'other-name' }), true)
  assert.equal(hasWorkspaceContent({ ...empty, tailnetAuthKeys: { 'tailnet-1': 'tskey-abc' } }), true)
  assert.equal(hasWorkspaceContent({
    ...empty,
    selectedSchemeID: DEFAULT_SELECTED_SCHEME_ID,
    exportConfigName: DEFAULT_EXPORT_CONFIG_NAME,
  }), false)
})

if (failures > 0) {
  console.error(`\n${failures} 项冲突自检失败`)
  process.exitCode = 1
} else {
  console.log('\n全部冲突自检通过')
}

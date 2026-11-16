// 方案区块：当前方案卡片与导入表单。
import type { RulesTabController } from '../../rules/useRulesTabController'
import { SchemeCard } from './SchemeCard'
import { SchemeImportCard } from './SchemeImportCard'

export function RulesSchemeSection({ controller }: { controller: RulesTabController }) {
  const {
    scheme,
    selectedMeta,
    customScheme,
    builtinForCustom,
    allMetas,
    selectedSchemeID,
    customSchemes,
    readOnly,
    refreshingScheme,
    schemeRules,
    remoteRefTotal,
    enabledForRules,
    selectedBuiltinOverride,
    selectedSnapshotHistory,
    selectedBuiltinResolution,
    snapshotFallbackNotice,
    workspaceMode,
    serverUpstream,
    serverUpstreamError,
    upstreamChecking,
    updatingBuiltinScheme,
    builtinSchemeOverrides,
    schemeSnapshots,
    checkBuiltinSchemeUpdatesOnOpen,
    setCheckBuiltinSchemeUpdatesOnOpen,
    builtinSchemeUpdateNotices,
    setBuiltinSchemeUpdateNotice,
    schemeError,
    setSchemeError,
    importingScheme,
    setImportingScheme,
    pendingFreeze,
    setPendingFreeze,
    setScheme,
    setRestoreInitialConfirm,
    setTextEditorScheme,
    setPendingSchemeDelete,
    beginEditScheme,
    autoFillGroupEmoji,
    refreshImportedScheme,
    beginEditNetwork,
    requestSnapshotRollback,
    checkUpstreamNow,
    freezeBuiltinScheme,
    copyBuiltinSchemeFromUpstream,
    restoreBuiltinSnapshot,
    confirmFreeze,
    schemeName,
    setSchemeName,
    schemeURL,
    setSchemeURL,
    schemeText,
    setSchemeText,
    schemeFileName,
    schemeLoading,
    readSchemeFile,
    importSchemeFromURL,
    importSchemeFromText,
    importSelfConfiguration,
  } = controller

  return (
    <>
      <SchemeCard
        scheme={scheme}
        selectedMeta={selectedMeta}
        customScheme={customScheme}
        builtinForCustom={builtinForCustom}
        allMetas={allMetas}
        selectedSchemeID={selectedSchemeID}
        customSchemes={customSchemes}
        readOnly={readOnly}
        refreshingScheme={refreshingScheme}
        schemeRules={schemeRules}
        remoteRefTotal={remoteRefTotal}
        enabledNodeCount={enabledForRules.length}
        selectedBuiltinOverride={selectedBuiltinOverride}
        selectedSnapshotHistory={selectedSnapshotHistory}
        selectedBuiltinResolution={selectedBuiltinResolution}
        snapshotFallbackNotice={snapshotFallbackNotice}
        workspaceMode={workspaceMode}
        serverUpstream={serverUpstream}
        serverUpstreamError={serverUpstreamError}
        upstreamChecking={upstreamChecking}
        updatingBuiltinScheme={updatingBuiltinScheme}
        builtinSchemeOverrides={builtinSchemeOverrides}
        schemeSnapshots={schemeSnapshots}
        checkBuiltinSchemeUpdatesOnOpen={checkBuiltinSchemeUpdatesOnOpen}
        setCheckBuiltinSchemeUpdatesOnOpen={setCheckBuiltinSchemeUpdatesOnOpen}
        builtinSchemeUpdateNotices={builtinSchemeUpdateNotices}
        setBuiltinSchemeUpdateNotice={setBuiltinSchemeUpdateNotice}
        schemeError={schemeError}
        importingScheme={importingScheme}
        pendingFreeze={pendingFreeze}
        setPendingFreeze={setPendingFreeze}
        setScheme={setScheme}
        setRestoreInitialConfirm={setRestoreInitialConfirm}
        setTextEditorScheme={setTextEditorScheme}
        setImportingScheme={setImportingScheme}
        setPendingSchemeDelete={setPendingSchemeDelete}
        beginEditScheme={beginEditScheme}
        autoFillGroupEmoji={autoFillGroupEmoji}
        refreshImportedScheme={refreshImportedScheme}
        beginEditNetwork={beginEditNetwork}
        requestSnapshotRollback={requestSnapshotRollback}
        checkUpstreamNow={checkUpstreamNow}
        freezeBuiltinScheme={freezeBuiltinScheme}
        copyBuiltinSchemeFromUpstream={copyBuiltinSchemeFromUpstream}
        restoreBuiltinSnapshot={restoreBuiltinSnapshot}
        confirmFreeze={confirmFreeze}
      />

      {importingScheme && (
        <SchemeImportCard
          readOnly={readOnly}
          name={schemeName}
          url={schemeURL}
          text={schemeText}
          fileName={schemeFileName}
          error={schemeError}
          loading={schemeLoading}
          onNameChange={setSchemeName}
          onURLChange={setSchemeURL}
          onTextChange={setSchemeText}
          onReadFile={(file) => void readSchemeFile(file)}
          onImportURL={importSchemeFromURL}
          onImportText={importSchemeFromText}
          onImportSelfConfiguration={() => void importSelfConfiguration()}
          onCancel={() => { setImportingScheme(false); setSchemeError(null) }}
        />
      )}

    </>
  )
}


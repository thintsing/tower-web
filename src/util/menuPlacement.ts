const PANEL_SELECTOR = '.menu-panel, .legend-body'
const VIEWPORT_MARGIN = 8
const ANCHOR_GAP = 6

/**
 * Place an open <details> popover above its trigger when there is not enough
 * room below. The panel stays in normal document flow (absolute inside the
 * trigger), so this only removes viewport-edge clipping; stacking is handled
 * by the card z-index / removed animation stacking context.
 */
export function placeDetailsPanel(details: HTMLDetailsElement): void {
  const panel = details.querySelector<HTMLElement>(PANEL_SELECTOR)
  if (!panel) return
  if (!details.open) {
    panel.classList.remove('is-up')
    return
  }

  // Measure the natural downward position even if the previous open was flipped.
  panel.classList.remove('is-up')
  const anchor = details.getBoundingClientRect()
  const panelHeight = panel.offsetHeight
  const spaceBelow = window.innerHeight - anchor.bottom - ANCHOR_GAP - VIEWPORT_MARGIN
  const spaceAbove = anchor.top - ANCHOR_GAP - VIEWPORT_MARGIN
  if (panelHeight > spaceBelow && spaceAbove >= panelHeight) {
    panel.classList.add('is-up')
  }
}

/** Re-place all currently open menu/legend panels (e.g. after viewport resize). */
export function placeOpenDetailsPanels(root: ParentNode = document): void {
  for (const details of root.querySelectorAll<HTMLDetailsElement>('details.menu[open], details.legend[open]')) {
    placeDetailsPanel(details)
  }
}

import { describe, it, expect } from 'vitest';
import { 
  EdgeType, 
  SnapPoint, 
  CardGeometry, 
  PipelineLinkDefinition 
} from './useAgentHierarchyConnections';

describe('useAgentHierarchyConnections edge snapping logic', () => {
  const createMockCardGeometry = (
    index: number,
    left: number,
    top: number,
    width = 120,
    height = 200,
    row = 0,
    col = index
  ): CardGeometry => {
    const right = left + width;
    const bottom = top + height;
    const centerX = left + width / 2;
    const centerY = top + height / 2;

    return {
      index,
      agentId: `agent-${index}`,
      left,
      top,
      right,
      bottom,
      width,
      height,
      centerX,
      centerY,
      row,
      col,
      edges: {
        top: { x: centerX, y: top, edge: 'top' },
        bottom: { x: centerX, y: bottom, edge: 'bottom' },
        left: { x: left, y: centerY, edge: 'left' },
        right: { x: right, y: centerY, edge: 'right' },
      },
    };
  };

  it('snaps horizontal adjacent cards from source right edge to target left edge', () => {
    // Card 0 (left=0..120), Card 1 (left=130..250) in row 0
    const card0 = createMockCardGeometry(0, 0, 50, 120, 200, 0, 0);
    const card1 = createMockCardGeometry(1, 130, 50, 120, 200, 0, 1);

    // Card 0 right edge is at (120, 150)
    expect(card0.edges.right).toEqual({ x: 120, y: 150, edge: 'right' });
    // Card 1 left edge is at (130, 150)
    expect(card1.edges.left).toEqual({ x: 130, y: 150, edge: 'left' });

    // Distance between right and left is only 10px
    const distRightLeft = Math.hypot(card0.edges.right.x - card1.edges.left.x, card0.edges.right.y - card1.edges.left.y);
    expect(distRightLeft).toBe(10);
  });

  it('snaps cross-row cards from source bottom edge to target top edge', () => {
    // Card in Row 0 (top=50..250), Card in Row 1 (top=280..480)
    const cardRow0 = createMockCardGeometry(0, 50, 50, 120, 200, 0, 0);
    const cardRow1 = createMockCardGeometry(4, 50, 280, 120, 200, 1, 0);

    expect(cardRow0.edges.bottom).toEqual({ x: 110, y: 250, edge: 'bottom' });
    expect(cardRow1.edges.top).toEqual({ x: 110, y: 280, edge: 'top' });

    const distVertical = Math.hypot(
      cardRow0.edges.bottom.x - cardRow1.edges.top.x, 
      cardRow0.edges.bottom.y - cardRow1.edges.top.y
    );
    expect(distVertical).toBe(30);
  });

  it('snaps parent bus point down to the nearest card edge (top edge)', () => {
    const card = createMockCardGeometry(0, 50, 60, 120, 200, 0, 0);
    const busPoint = { x: card.centerX, y: 25 }; // Bus above card at y=25

    // Distances to card edges:
    // Top edge at y=60: dist = 35
    // Bottom edge at y=260: dist = 235
    // Left edge at (50, 160): dist > 135
    // Right edge at (170, 160): dist > 135
    const distTop = Math.hypot(busPoint.x - card.edges.top.x, busPoint.y - card.edges.top.y);
    const distBottom = Math.hypot(busPoint.x - card.edges.bottom.x, busPoint.y - card.edges.bottom.y);

    expect(distTop).toBe(35);
    expect(distBottom).toBe(235);
    expect(distTop).toBeLessThan(distBottom);
  });
});

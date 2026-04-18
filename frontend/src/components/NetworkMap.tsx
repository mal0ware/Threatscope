import { useCallback, useEffect, useRef } from 'react';
import * as d3 from 'd3';
import { searchEvents } from '../lib/api';
import { useAPI } from '../hooks/useAPI';

interface Node {
  id: string;
  group: 'internal' | 'external';
  eventCount: number;
}

interface Link {
  source: string;
  target: string;
  count: number;
}

function buildGraph(events: { source_ip: string | null; dest_ip: string | null }[]) {
  const nodeMap = new Map<string, Node>();
  const linkMap = new Map<string, Link>();

  for (const e of events) {
    const src = e.source_ip ?? 'local';
    const dst = e.dest_ip ?? 'local';
    if (src === dst) continue;

    if (!nodeMap.has(src)) {
      nodeMap.set(src, {
        id: src,
        group: src.startsWith('10.') || src.startsWith('192.168.') ? 'internal' : 'external',
        eventCount: 0,
      });
    }
    nodeMap.get(src)!.eventCount++;

    if (!nodeMap.has(dst)) {
      nodeMap.set(dst, {
        id: dst,
        group: dst.startsWith('10.') || dst.startsWith('192.168.') ? 'internal' : 'external',
        eventCount: 0,
      });
    }

    const linkKey = `${src}->${dst}`;
    if (!linkMap.has(linkKey)) {
      linkMap.set(linkKey, { source: src, target: dst, count: 0 });
    }
    linkMap.get(linkKey)!.count++;
  }

  return {
    nodes: Array.from(nodeMap.values()),
    links: Array.from(linkMap.values()),
  };
}

export function NetworkMap() {
  const svgRef = useRef<SVGSVGElement>(null);
  const fetcher = useCallback(() => searchEvents({ limit: 200 }), []);
  const { data } = useAPI(fetcher, 30000);

  useEffect(() => {
    if (!data || !svgRef.current) return;

    const { nodes, links } = buildGraph(data.events);
    if (nodes.length === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const width = svgRef.current.clientWidth;
    const height = 300;

    const simulation = d3
      .forceSimulation(nodes as d3.SimulationNodeDatum[])
      .force(
        'link',
        d3
          .forceLink(links as d3.SimulationLinkDatum<d3.SimulationNodeDatum>[])
          .id((d: any) => d.id)
          .distance(80),
      )
      .force('charge', d3.forceManyBody().strength(-200))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(20));

    const link = svg
      .append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', '#374151')
      .attr('stroke-width', (d) => Math.min(d.count / 2, 4));

    const node = svg
      .append('g')
      .selectAll('circle')
      .data(nodes)
      .join('circle')
      .attr('r', (d) => Math.max(4, Math.min(Math.sqrt(d.eventCount) * 2, 16)))
      .attr('fill', (d) => (d.group === 'internal' ? '#3b82f6' : '#ef4444'))
      .attr('stroke', '#1f2937')
      .attr('stroke-width', 1.5);

    const label = svg
      .append('g')
      .selectAll('text')
      .data(nodes)
      .join('text')
      .text((d) => d.id)
      .attr('font-size', 10)
      .attr('fill', '#9ca3af')
      .attr('dx', 12)
      .attr('dy', 4);

    node.append('title').text((d) => `${d.id} (${d.eventCount} events)`);

    simulation.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);
      node.attr('cx', (d: any) => d.x).attr('cy', (d: any) => d.y);
      label.attr('x', (d: any) => d.x).attr('y', (d: any) => d.y);
    });

    return () => {
      simulation.stop();
    };
  }, [data]);

  return (
    <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4">
      <h2 className="text-lg font-semibold mb-4">Network Map</h2>
      <div className="flex gap-4 mb-2 text-xs text-[var(--color-text-muted)]">
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-blue-500" /> Internal
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-red-500" /> External
        </span>
      </div>
      <svg ref={svgRef} width="100%" height={300} className="rounded" />
    </div>
  );
}

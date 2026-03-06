"use client";

import * as d3 from "d3";
import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";

type Bucket = {
  bucket: string;
  count: number;
};

export function TimelineChart({
  data,
  from,
  bucketSize
}: {
  data: Bucket[];
  from: string;
  bucketSize: "minute" | "hour";
}) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [hover, setHover] = useState<Bucket | null>(null);
  const router = useRouter();

  const parsed = useMemo(
    () =>
      data.map((d) => ({
        ...d,
        date: new Date(d.bucket)
      })),
    [data]
  );

  useEffect(() => {
    if (!svgRef.current || parsed.length === 0) return;
    const svg = d3.select(svgRef.current);
    const width = svgRef.current.clientWidth || 800;
    const height = 260;
    svg.attr("viewBox", `0 0 ${width} ${height}`);

    const maxCount = d3.max(parsed, (d) => d.count) || 1;
    const x = d3
      .scaleTime()
      .domain(d3.extent(parsed, (d) => d.date) as [Date, Date])
      .range([50, width - 20]);
    const y = d3
      .scaleLinear()
      .domain([0, maxCount])
      .nice()
      .range([height - 30, 10]);

    const threshold = d3.quantile(
      parsed.map((d) => d.count).sort((a, b) => a - b),
      0.9
    );

    svg.selectAll("*").remove();

    const container = svg.append("g");

    const bars = container
      .selectAll("rect")
      .data(parsed)
      .enter()
      .append("rect")
      .attr("x", (d) => x(d.date) - 5)
      .attr("width", () => Math.max(6, (width - 80) / parsed.length))
      .attr("y", (d) => y(d.count))
      .attr("height", (d) => y(0) - y(d.count))
      .attr("rx", 2)
      .attr("fill", (d) =>
        threshold && d.count >= threshold ? "#cc0000" : "#00b7ff"
      )
      .attr("opacity", 0.85)
      .on("mousemove", (_event, d) => setHover(d))
      .on("mouseleave", () => setHover(null))
      .on("click", (_event, d) => {
        const start = d.bucket;
        const end = bucketSize === "hour"
          ? new Date(new Date(start).getTime() + 60 * 60 * 1000).toISOString()
          : new Date(new Date(start).getTime() + 60 * 1000).toISOString();
        router.push(`/events?from=${encodeURIComponent(start)}&to=${encodeURIComponent(end)}`);
      });

    const xAxis = d3.axisBottom(x).ticks(6).tickSizeOuter(0);
    const yAxis = d3.axisLeft(y).ticks(5).tickSizeOuter(0);

    container
      .append("g")
      .attr("transform", `translate(0,${height - 30})`)
      .call(xAxis)
      .selectAll("text")
      .attr("fill", "#e5e5e5")
      .attr("font-size", "10px");

    container
      .append("g")
      .attr("transform", "translate(50,0)")
      .call(yAxis)
      .selectAll("text")
      .attr("fill", "#e5e5e5")
      .attr("font-size", "10px");

    const zoomed = (event: d3.D3ZoomEvent<SVGSVGElement, unknown>) => {
      const zx = event.transform.rescaleX(x);
      bars
        .attr("x", (d) => zx(d.date) - 5)
        .attr("width", () => Math.max(6, (width - 80) / parsed.length));
      container
        .selectAll<SVGGElement, unknown>("g.x-axis")
        .data([0])
        .join("g")
        .attr("class", "x-axis")
        .attr("transform", `translate(0,${height - 30})`)
        .call(d3.axisBottom(zx).ticks(6).tickSizeOuter(0))
        .selectAll("text")
        .attr("fill", "#cbd5e1")
        .attr("font-size", "10px");
    };

    svg.call(
      d3
        .zoom<SVGSVGElement, unknown>()
        .scaleExtent([1, 20])
        .translateExtent([
          [0, 0],
          [width, height]
        ])
        .extent([
          [0, 0],
          [width, height]
        ])
        .on("zoom", zoomed)
    );
  }, [parsed, bucketSize]);

  return (
    <div className="relative">
      <svg ref={svgRef} className="w-full h-[280px] bg-slate-900/60 rounded-lg border border-slate-800/60" />
      {hover && (
        <div className="absolute top-2 right-2 bg-slate-900/90 border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 shadow-lg">
          <div>{hover.bucket}</div>
          <div className="font-semibold">Count: {hover.count}</div>
        </div>
      )}
    </div>
  );
}

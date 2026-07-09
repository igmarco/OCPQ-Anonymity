import { CalendarIcon } from "@radix-ui/react-icons";
import * as React from "react";
import type { DateRange } from "react-day-picker";

import { Button } from "@/components/ui/button";
import { Calendar } from "@/components/ui/calendar";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { cn } from "@/lib/utils";

const pad = (n: number) => String(n).padStart(2, "0");
const utcDate = (d: Date) =>
	`${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;

/** Build a UTC ISO string from date/hour/minute fields, or null if invalid. */
function buildIso(dateStr: string, hourStr: string, minStr: string): string | null {
	const dm = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateStr.trim());
	if (!dm) return null;
	const y = +dm[1];
	const mo = +dm[2];
	const d = +dm[3];
	const hh = hourStr.trim() === "" ? 0 : Number(hourStr);
	const mm = minStr.trim() === "" ? 0 : Number(minStr);
	if (!Number.isInteger(hh) || !Number.isInteger(mm)) return null;
	if (mo < 1 || mo > 12 || d < 1 || d > 31 || hh < 0 || hh > 23 || mm < 0 || mm > 59) return null;
	const back = new Date(Date.UTC(y, mo - 1, d, hh, mm, 0, 0));
	if (back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d) {
		return null;
	}
	return back.toISOString();
}

type Mode = "before" | "after" | "between";
type FieldKey = "fromDate" | "fromHour" | "fromMin" | "toDate" | "toHour" | "toMin";
type Draft = Record<FieldKey, string>;

function sideDraft(iso: string | null): { date: string; hour: string; min: string } {
	if (!iso) return { date: "", hour: "", min: "" };
	const d = new Date(iso);
	if (Number.isNaN(d.getTime())) return { date: "", hour: "", min: "" };
	return { date: utcDate(d), hour: pad(d.getUTCHours()), min: pad(d.getUTCMinutes()) };
}

function toDraft(from: string | null, to: string | null): Draft {
	const f = sideDraft(from);
	const t = sideDraft(to);
	return {
		fromDate: f.date,
		fromHour: f.hour,
		fromMin: f.min,
		toDate: t.date,
		toHour: t.hour,
		toMin: t.min,
	};
}

function deriveMode(from: string | null, to: string | null, fallback: Mode): Mode {
	if (from && to) return "between";
	if (from && !to) return "after";
	if (!from && to) return "before";
	return fallback;
}

/** Resolve one bound's fields: empty date => open (null); valid => ISO; partial => keep prev. */
function resolveSide(date: string, hour: string, min: string, prev: string | null): string | null {
	if (!date.trim()) return null;
	return buildIso(date, hour, min) ?? prev;
}

function computeBounds(
	mode: Mode,
	d: Draft,
	prevFrom: string | null,
	prevTo: string | null,
): { from: string | null; to: string | null } {
	const f = resolveSide(d.fromDate, d.fromHour, d.fromMin, prevFrom);
	const t = resolveSide(d.toDate, d.toHour, d.toMin, prevTo);
	switch (mode) {
		case "after":
			return { from: f, to: null };
		case "before":
			return { from: null, to: t };
		case "between":
			return { from: f, to: t };
	}
}

const MODES: { value: Mode; label: string }[] = [
	{ value: "before", label: "Before" },
	{ value: "after", label: "After" },
	{ value: "between", label: "Between" },
];

export function DateTimeRangeInput({
	from,
	to,
	onChange,
	className,
}: {
	from: string | null;
	to: string | null;
	onChange: (next: { from: string | null; to: string | null }) => void;
	className?: string;
}) {
	const [draft, setDraft] = React.useState(() => toDraft(from, to));
	const [mode, setMode] = React.useState<Mode>(() => deriveMode(from, to, "after"));
	const [open, setOpen] = React.useState(false);
	// Guards resync: our own emitted value must not reformat fields mid-edit.
	const lastEmitted = React.useRef<{ from: string | null; to: string | null }>({ from, to });

	React.useEffect(() => {
		if (from === lastEmitted.current.from && to === lastEmitted.current.to) return;
		lastEmitted.current = { from, to };
		setDraft(toDraft(from, to));
		setMode((m) => deriveMode(from, to, m));
	}, [from, to]);

	function emit(next: Draft) {
		setDraft(next);
		const bounds = computeBounds(mode, next, from, to);
		lastEmitted.current = bounds;
		onChange(bounds);
	}

	function changeMode(next: string) {
		if (!next) return;
		const m = next as Mode;
		let d = draft;
		// Carry the value between after (from) and before (to); drop unused side from between.
		if (mode === "after" && m === "before") {
			d = {
				...draft,
				toDate: draft.fromDate,
				toHour: draft.fromHour,
				toMin: draft.fromMin,
				fromDate: "",
				fromHour: "",
				fromMin: "",
			};
		} else if (mode === "before" && m === "after") {
			d = {
				...draft,
				fromDate: draft.toDate,
				fromHour: draft.toHour,
				fromMin: draft.toMin,
				toDate: "",
				toHour: "",
				toMin: "",
			};
		} else if (mode === "between" && m === "after") {
			d = { ...draft, toDate: "", toHour: "", toMin: "" };
		} else if (mode === "between" && m === "before") {
			d = { ...draft, fromDate: "", fromHour: "", fromMin: "" };
		}
		setMode(m);
		setDraft(d);
		const bounds = computeBounds(m, d, from, to);
		lastEmitted.current = bounds;
		onChange(bounds);
	}

	function setField(key: FieldKey, value: string) {
		emit({ ...draft, [key]: value });
	}

	function normalize() {
		setDraft(toDraft(lastEmitted.current.from, lastEmitted.current.to));
	}

	function handleRangeSelect(range: DateRange | undefined) {
		const next = { ...draft };
		next.fromDate = range?.from ? utcDate(range.from) : "";
		next.toDate = range?.to ? utcDate(range.to) : "";
		if (next.fromDate && !next.fromHour) next.fromHour = "00";
		if (next.fromDate && !next.fromMin) next.fromMin = "00";
		if (next.toDate && !next.toHour) next.toHour = "00";
		if (next.toDate && !next.toMin) next.toMin = "00";
		if (!next.fromDate) {
			next.fromHour = "";
			next.fromMin = "";
		}
		if (!next.toDate) {
			next.toHour = "";
			next.toMin = "";
		}
		emit(next);
	}

	function handleSingleSelect(day: Date | undefined) {
		if (!day) return;
		const dateStr = utcDate(day);
		const next = { ...draft };
		if (mode === "before") {
			next.toDate = dateStr;
			if (!next.toHour) next.toHour = "00";
			if (!next.toMin) next.toMin = "00";
		} else {
			next.fromDate = dateStr;
			if (!next.fromHour) next.fromHour = "00";
			if (!next.fromMin) next.fromMin = "00";
		}
		emit(next);
		setOpen(false);
	}

	const datePlaceholder = `${new Date().getFullYear()}-01-01`;
	const dateInput = (key: FieldKey, label: string) => (
		<Input
			type="text"
			inputMode="numeric"
			aria-label={label}
			placeholder={datePlaceholder}
			className="h-8 w-[7.5rem] font-mono text-xs"
			value={draft[key]}
			onChange={(ev) => setField(key, ev.currentTarget.value)}
			onBlur={normalize}
		/>
	);

	const timeInput = (hKey: FieldKey, mKey: FieldKey) => (
		<span className="inline-flex items-center font-mono text-xs">
			<Input
				inputMode="numeric"
				maxLength={2}
				aria-label="Hour"
				placeholder="00"
				className="h-8 w-9 px-1 text-center"
				value={draft[hKey]}
				onChange={(ev) => setField(hKey, ev.currentTarget.value)}
				onBlur={normalize}
			/>
			<span className="px-0.5 text-muted-foreground">:</span>
			<Input
				inputMode="numeric"
				maxLength={2}
				aria-label="Minute"
				placeholder="00"
				className="h-8 w-9 px-1 text-center"
				value={draft[mKey]}
				onChange={(ev) => setField(mKey, ev.currentTarget.value)}
				onBlur={normalize}
			/>
		</span>
	);

	const rangeSelected: DateRange | undefined = from
		? { from: new Date(from), to: to ? new Date(to) : undefined }
		: to
			? { from: new Date(to), to: new Date(to) }
			: undefined;
	const singleSelected =
		mode === "before" ? (to ? new Date(to) : undefined) : from ? new Date(from) : undefined;

	const fieldRow = (label: string, dateKey: FieldKey, hKey: FieldKey, mKey: FieldKey) => (
		<div className="flex items-center gap-2">
			<span className="w-10 text-right text-xs text-muted-foreground">{label}</span>
			{dateInput(dateKey, `${label} date`)}
			{timeInput(hKey, mKey)}
			<span className="text-xs text-muted-foreground">UTC</span>
		</div>
	);

	return (
		<div className={cn("flex flex-col items-start gap-2", className)}>
			<ToggleGroup
				type="single"
				value={mode}
				onValueChange={changeMode}
				size="sm"
				variant="outline"
			>
				{MODES.map((m) => (
					<ToggleGroupItem key={m.value} value={m.value} className="h-8 px-3 text-xs">
						{m.label}
					</ToggleGroupItem>
				))}
			</ToggleGroup>

			<div className="flex flex-col gap-1">
				{mode === "after" && fieldRow("from", "fromDate", "fromHour", "fromMin")}
				{mode === "before" && fieldRow("to", "toDate", "toHour", "toMin")}
				{mode === "between" && (
					<>
						{fieldRow("from", "fromDate", "fromHour", "fromMin")}
						{fieldRow("to", "toDate", "toHour", "toMin")}
					</>
				)}
			</div>

			<div className="flex items-center gap-2">
				<Popover open={open} onOpenChange={setOpen}>
					<PopoverTrigger asChild>
						<Button variant="outline" size="sm" type="button" className="h-8 gap-2">
							<CalendarIcon className="size-4" />
							{mode === "between" ? "Pick range" : "Pick date"}
						</Button>
					</PopoverTrigger>
					<PopoverContent className="w-auto p-0" align="start">
						{mode === "between" ? (
							<Calendar
								mode="range"
								timeZone="utc"
								selected={rangeSelected}
								onSelect={handleRangeSelect}
								defaultMonth={rangeSelected?.from}
								numberOfMonths={2}
							/>
						) : (
							<Calendar
								mode="single"
								timeZone="utc"
								selected={singleSelected}
								onSelect={handleSingleSelect}
								defaultMonth={singleSelected}
							/>
						)}
					</PopoverContent>
				</Popover>
			</div>
		</div>
	);
}

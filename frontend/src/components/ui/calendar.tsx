import { ChevronLeftIcon, ChevronRightIcon } from "@radix-ui/react-icons";
import type * as React from "react";
import { DayPicker } from "react-day-picker";

import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type CalendarProps = React.ComponentProps<typeof DayPicker>;

function Calendar({ className, classNames, showOutsideDays = true, ...props }: CalendarProps) {
	return (
		<DayPicker
			showOutsideDays={showOutsideDays}
			className={cn("p-3", className)}
			classNames={{
				months: "flex flex-col sm:flex-row gap-2",
				month: "flex flex-col gap-4",
				month_caption: "flex justify-center pt-1 relative items-center w-full",
				caption_label: "text-sm font-medium",
				nav: "flex items-center gap-1 absolute inset-x-0 top-0 justify-between px-1",
				button_previous: cn(
					buttonVariants({ variant: "outline" }),
					"size-7 bg-transparent p-0 opacity-50 hover:opacity-100",
				),
				button_next: cn(
					buttonVariants({ variant: "outline" }),
					"size-7 bg-transparent p-0 opacity-50 hover:opacity-100",
				),
				month_grid: "w-full border-collapse space-x-1",
				weekdays: "flex",
				weekday: "text-muted-foreground rounded-md w-8 font-normal text-[0.8rem]",
				week: "flex w-full mt-2",
				day: cn(
					"relative p-0 text-center text-sm focus-within:relative focus-within:z-20",
					"[&:has([aria-selected])]:bg-accent [&:has([aria-selected].day-range-end)]:rounded-r-md",
				),
				day_button: cn(
					buttonVariants({ variant: "ghost" }),
					"size-8 p-0 font-normal aria-selected:opacity-100",
				),
				selected:
					"[&>button]:bg-foreground [&>button]:text-primary-foreground [&>button]:hover:bg-foreground [&>button]:hover:text-primary-foreground [&>button]:focus:bg-foreground [&>button]:focus:text-primary-foreground",
				range_start: "rounded-l-md",
				range_end: "rounded-r-md",
				range_middle:
					"[&>button]:!bg-accent [&>button]:!text-accent-foreground [&>button]:!rounded-none [&>button]:hover:!bg-accent",
				today: "[&>button]:bg-accent [&>button]:text-accent-foreground",
				outside: "text-muted-foreground opacity-50",
				disabled: "text-muted-foreground opacity-50",
				hidden: "invisible",
				...classNames,
			}}
			components={{
				Chevron: ({ orientation }) =>
					orientation === "left" ? (
						<ChevronLeftIcon className="size-4" />
					) : (
						<ChevronRightIcon className="size-4" />
					),
			}}
			{...props}
		/>
	);
}
Calendar.displayName = "Calendar";

export { Calendar };

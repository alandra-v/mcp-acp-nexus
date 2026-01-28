import { useState, Fragment } from 'react'
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type VisibilityState,
  type Row,
} from '@tanstack/react-table'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { ScrollArea } from '@/components/ui/scroll-area'
import { cn } from '@/lib/utils'
import { ChevronDown, ChevronRight } from 'lucide-react'

interface DataTableProps<TData> {
  columns: ColumnDef<TData>[]
  data: TData[]
  defaultColumnVisibility?: VisibilityState
  onLoadMore?: () => void
  hasMore?: boolean
  loading?: boolean
  renderExpandedRow?: (row: Row<TData>) => React.ReactNode
}

export function DataTable<TData>({
  columns,
  data,
  defaultColumnVisibility = {},
  onLoadMore,
  hasMore = false,
  loading = false,
  renderExpandedRow,
}: DataTableProps<TData>) {
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>(defaultColumnVisibility)
  const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({})

  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
    onColumnVisibilityChange: setColumnVisibility,
    state: {
      columnVisibility,
    },
  })

  const toggleRowExpanded = (rowId: string) => {
    setExpandedRows((prev) => ({
      ...prev,
      [rowId]: !prev[rowId],
    }))
  }

  return (
    <div className="rounded-lg border border-[var(--border-subtle)] card-gradient overflow-hidden">
      <ScrollArea className="min-h-[200px] max-h-[600px]">
      <Table>
        <TableHeader>
          {table.getHeaderGroups().map((headerGroup) => (
            <TableRow
              key={headerGroup.id}
              className="border-b border-[var(--border-subtle)] hover:bg-transparent"
            >
              {renderExpandedRow && (
                <TableHead className="w-8 px-2" />
              )}
              {headerGroup.headers.map((header) => (
                <TableHead
                  key={header.id}
                  className="text-xs font-medium text-base-500 uppercase tracking-wider"
                >
                  {header.isPlaceholder
                    ? null
                    : flexRender(header.column.columnDef.header, header.getContext())}
                </TableHead>
              ))}
            </TableRow>
          ))}
        </TableHeader>
        <TableBody>
          {table.getRowModel().rows?.length ? (
            table.getRowModel().rows.map((row) => (
              <Fragment key={row.id}>
                <TableRow
                  data-state={row.getIsSelected() && 'selected'}
                  className={cn(
                    'border-b border-[var(--border-subtle)] hover:bg-base-900/50 transition-smooth',
                    renderExpandedRow && 'cursor-pointer',
                    expandedRows[row.id] && 'bg-base-900/30'
                  )}
                  onClick={() => renderExpandedRow && toggleRowExpanded(row.id)}
                  onKeyDown={(e) => {
                    if (renderExpandedRow && (e.key === 'Enter' || e.key === ' ')) {
                      e.preventDefault()
                      toggleRowExpanded(row.id)
                    }
                  }}
                  tabIndex={renderExpandedRow ? 0 : undefined}
                  aria-expanded={renderExpandedRow ? expandedRows[row.id] : undefined}
                >
                  {renderExpandedRow && (
                    <TableCell className="w-8 px-2 text-base-500">
                      {expandedRows[row.id] ? (
                        <ChevronDown className="w-4 h-4" aria-hidden="true" />
                      ) : (
                        <ChevronRight className="w-4 h-4" aria-hidden="true" />
                      )}
                      <span className="sr-only">
                        {expandedRows[row.id] ? 'Collapse row' : 'Expand row'}
                      </span>
                    </TableCell>
                  )}
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id} className="py-2 text-sm">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
                {expandedRows[row.id] && renderExpandedRow && (
                  <TableRow key={`${row.id}-expanded`} className="hover:bg-transparent">
                    <TableCell
                      colSpan={columns.length + 1}
                      className="p-0 border-b border-[var(--border-subtle)]"
                    >
                      {renderExpandedRow(row)}
                    </TableCell>
                  </TableRow>
                )}
              </Fragment>
            ))
          ) : (
            <TableRow>
              <TableCell
                colSpan={columns.length + (renderExpandedRow ? 1 : 0)}
                className="h-24 text-center text-base-500"
              >
                {loading ? 'Loading...' : 'No results'}
              </TableCell>
            </TableRow>
          )}
          {hasMore && (
            <TableRow className="hover:bg-transparent">
              <TableCell
                colSpan={columns.length + (renderExpandedRow ? 1 : 0)}
                className="text-center py-4"
              >
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    onLoadMore?.()
                  }}
                  disabled={loading}
                  className="text-sm text-base-400 hover:text-foreground transition-smooth disabled:opacity-50"
                >
                  {loading ? 'Loading...' : 'Load more'}
                </button>
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
      </ScrollArea>
    </div>
  )
}

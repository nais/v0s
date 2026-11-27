package database

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

type PageDirection int

const (
	PageForward PageDirection = iota
	PageBackward
)

type PageInfo struct {
	HasNextPage     bool
	HasPreviousPage bool
}

func (p Page) validate() error {
	if p.Direction != PageForward && p.Direction != PageBackward {
		return fmt.Errorf("invalid page direction: %w", ErrInvalid)
	}
	return nil
}

type keysetTerm struct {
	column string
	desc   bool
}

type keysetOrder []keysetTerm

func (o keysetOrder) sql(backward bool) string {
	terms := make([]string, len(o))
	for i, term := range o {
		direction := "ASC"
		if term.desc != backward {
			direction = "DESC"
		}
		terms[i] = term.column + " " + direction
	}
	return strings.Join(terms, ", ")
}

func (o keysetOrder) seek(values []any, args *sqlArgs, backward, inclusive bool) string {
	params := make([]string, len(values))
	for i, value := range values {
		params[i] = args.add(value)
	}
	if len(o) > 1 {
		sameDirection := true
		columns := make([]string, len(o))
		for i, term := range o {
			columns[i] = term.column
			sameDirection = sameDirection && term.desc == o[0].desc
		}
		if sameDirection {
			op := ">"
			if o[0].desc != backward {
				op = "<"
			}
			if inclusive {
				op += "="
			}
			return "(" + strings.Join(columns, ", ") + ") " + op + " (" + strings.Join(params, ", ") + ")"
		}
	}
	terms := make([]string, len(o))
	var equal []string
	for i, term := range o {
		op := ">"
		if term.desc != backward {
			op = "<"
		}
		if inclusive && i == len(o)-1 {
			op += "="
		}
		terms[i] = "(" + and(append(equal, term.column+" "+op+" "+params[i])) + ")"
		equal = append(equal, term.column+" = "+params[i])
	}
	return "(" + strings.Join(terms, " OR ") + ")"
}

func keysetPageInfo(ctx context.Context, q pgx.Tx, existsPrefix string, args sqlArgs,
	order keysetOrder, page Page, edge []any, empty, more bool,
) (PageInfo, error) {
	info := PageInfo{HasNextPage: more}
	if page.Direction == PageBackward {
		info = PageInfo{HasPreviousPage: more}
	}
	if len(edge) == 0 {
		return info, nil
	}
	seek := order.seek(edge, &args, page.Direction != PageBackward, empty)
	var opposite bool
	if err := q.QueryRow(ctx, existsPrefix+seek+")", args...).Scan(&opposite); err != nil {
		return PageInfo{}, fmt.Errorf("checking pagination boundary: %w", err)
	}
	if page.Direction == PageBackward {
		info.HasNextPage = opposite
	} else {
		info.HasPreviousPage = opposite
	}
	return info, nil
}

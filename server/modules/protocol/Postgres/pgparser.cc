/*
 * Copyright (c) 2023 Pg plc
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.pg.com/bsl11.
 *
 * Change Date: 2026-12-27
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */

#include "pgparser.hh"
#include "postgresprotocol.hh"

namespace
{

struct ThisUnit
{
    PgParser::Helper helper;
} this_unit;

}

// static
const PgParser::Helper& PgParser::Helper::get()
{
    return this_unit.helper;
}

GWBUF PgParser::Helper::create_packet(std::string_view sql) const
{
    return pg::create_query_packet(sql);
}

mxs::Parser::PacketTypeMask PgParser::Helper::get_packet_type_mask(const GWBUF& packet) const
{
    uint32_t type_mask = mxs::sql::TYPE_UNKNOWN;
    TypeMaskStatus status = TypeMaskStatus::FINAL;

    if (packet.length() > 1)
    {
        switch (*packet.data())
        {
        case pg::QUERY:
        case pg::PARSE:
            status = TypeMaskStatus::NEEDS_PARSING;
            break;

            // TODO: Handle other packets appropriately.
        default:
            break;
        }
    }

    return PacketTypeMask { type_mask, status };
}

std::string_view PgParser::Helper::get_sql(const GWBUF& packet) const
{
    return pg::get_sql(packet);
}

bool PgParser::Helper::is_multi_part_packet(const GWBUF& packet) const
{
    return false;
}

bool PgParser::Helper::is_prepare(const GWBUF& packet) const
{
    return pg::is_prepare(packet);
}


PgParser::PgParser(std::unique_ptr<Parser> sParser)
    : mxs::CachingParser(std::move(sParser))
{
}

PgParser::~PgParser()
{
}

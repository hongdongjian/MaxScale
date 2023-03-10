/*
 * Copyright (c) 2023 MariaDB plc, Finnish Branch
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2027-02-21
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */
#pragma once

#include <maxpgsql/pg_connector.hh>
#include <maxscale/ccdefs.hh>
#include <maxscale/monitor.hh>

class PgServer : public mxs::MonitorServer
{
public:
    PgServer(SERVER* server, const SharedSettings& shared);

    void          test_permissions(const std::string& query) override;
    ConnectResult ping_or_connect() override;
    void          close_conn() override;
    void          fetch_uptime() override;
    void          update_disk_space_status() override;

private:
    mxp::PgSQL m_conn;

    bool fetch_variables() override;
};
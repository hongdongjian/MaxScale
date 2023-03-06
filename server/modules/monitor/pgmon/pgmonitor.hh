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

#include <maxscale/ccdefs.hh>
#include <unordered_map>
#include <maxscale/monitor.hh>

class PgServer;
class PgMonitor : public maxscale::SimpleMonitor
{
public:
    ~PgMonitor();
    static PgMonitor* create(const std::string& name, const std::string& module);
    json_t*           diagnostics() const override;
    json_t*           diagnostics(mxs::MonitorServer* server) const override;

    mxs::config::Configuration& configuration() override final;

protected:
    bool has_sufficient_permissions() override;
    void update_server_status(mxs::MonitorServer* monitored_server) override;
    void pre_tick() override;
    void post_tick() override;
    bool can_be_disabled(const mxs::MonitorServer& server, DisableType type,
                         std::string* errmsg_out) const override;

    class Config : public mxs::config::Configuration
    {
    public:
        Config(const std::string& name, PgMonitor* monitor);

        bool post_configure(const std::map<std::string, mxs::ConfigParameters>& nested_params) override final;


    private:
        PgMonitor* m_monitor;
    };

private:
    Config      m_config;
    PgMonitor(const std::string& name, const std::string& module);

    bool        post_configure();
    friend bool Config::post_configure(const std::map<std::string, mxs::ConfigParameters>& nested_params);
};

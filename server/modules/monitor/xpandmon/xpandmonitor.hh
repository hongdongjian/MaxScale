/*
 * Copyright (c) 2018 MariaDB Corporation Ab
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

#include "xpandmon.hh"
#include <map>
#include <set>
#include <sqlite3.h>
#include <maxscale/config2.hh>
#include <maxscale/monitor.hh>
#include <maxbase/http.hh>
#include "xpandmembership.hh"
#include "xpandnode.hh"

namespace config = maxscale::config;

class XpandServer;
class XpandMonitor : public maxscale::Monitor
                   , private XpandNode::Persister
{
    XpandMonitor(const XpandMonitor&) = delete;
    XpandMonitor& operator=(const XpandMonitor&) = delete;
public:
    class Config : public config::Configuration
    {
    public:
        Config(const std::string& name, XpandMonitor* pMonitor);

        bool post_configure(const std::map<std::string, mxs::ConfigParameters>& nested_params) override final;

        long cluster_monitor_interval() const
        {
            return m_cluster_monitor_interval.get().count();
        }

        long health_check_threshold() const
        {
            return m_health_check_threshold.get();
        }

        bool dynamic_node_detection() const
        {
            return m_dynamic_node_detection.get();
        }

        int health_check_port() const
        {
            return m_health_check_port.get();
        }

    private:
        config::Duration<std::chrono::milliseconds> m_cluster_monitor_interval;
        config::Count                               m_health_check_threshold;
        config::Bool                                m_dynamic_node_detection;
        config::Integer                             m_health_check_port;
        XpandMonitor*                               m_pMonitor;
    };

    ~XpandMonitor();

    static XpandMonitor* create(const std::string& name, const std::string& module);

    bool softfail(SERVER* pServer, json_t** ppError);
    bool unsoftfail(SERVER* pServer, json_t** ppError);

    json_t* diagnostics() const override;

    mxs::config::Configuration& configuration() override final;

    static mxs::config::Specification* specification();

private:
    XpandMonitor(const std::string& name,
                 const std::string& module,
                 sqlite3* pDb);

    void pre_loop() override;
    void post_loop() override;

    void tick() override;

    bool query(MYSQL* pCon, const char* zQuery);

    void check_bootstrap_servers();
    bool remove_persisted_information();
    void persist_bootstrap_servers();

    void notify_of_group_change(bool was_group_change);
    void set_volatile_down();

    void check_cluster(xpand::Softfailed softfailed);
    void check_hub(xpand::Softfailed softfailed);
    void choose_hub(xpand::Softfailed softfailed);

    void choose_dynamic_hub(xpand::Softfailed softfailed, std::set<std::string>& ips_checked);
    void choose_bootstrap_hub(xpand::Softfailed softfailed, std::set<std::string>& ips_checked);
    bool refresh_using_persisted_nodes(std::set<std::string>& ips_checked);

    bool refresh_nodes();
    bool refresh_nodes(MYSQL* pHub_con);
    bool check_cluster_membership(MYSQL* pHub_con,
                                  std::map<int, XpandMembership>* pMemberships);

    bool using_proxy_protocol() const;
    void populate_from_bootstrap_servers();

    void add_server(SERVER* it);

    void update_server_statuses();

    SERVER* create_volatile_server(const std::string& name, const std::string& ip, int port);

    void make_health_check();
    void initiate_delayed_http_check();
    bool check_http();
    void update_http_urls();

    bool get_extra_settings(mxs::ConfigParameters* pExtra) const;

    bool perform_softfail(SERVER* pServer, json_t** ppError);
    bool perform_unsoftfail(SERVER* pServer, json_t** ppError);

    enum class Operation
    {
        SOFTFAIL,
        UNSOFTFAIL,
    };

    bool perform_operation(Operation operation,
                           SERVER* pServer,
                           json_t** ppError);


    bool is_time_for_cluster_check() const
    {
        return now() - m_last_cluster_check > m_config.cluster_monitor_interval();
    }

    bool should_check_cluster() const
    {
        return m_is_group_change || is_time_for_cluster_check();
    }

    void trigger_cluster_check()
    {
        m_last_cluster_check = 0;
    }

    void cluster_checked()
    {
        m_last_cluster_check = now();
    }

    static long now()
    {
        return mxb::WorkerLoad::get_time_ms(mxb::Clock::now());
    }

    // XpandNode::Persister
    void persist(const XpandNode& node) override;
    void unpersist(const XpandNode& node) override;

    bool        post_configure();
    friend bool Config::post_configure(const std::map<std::string, mxs::ConfigParameters>& nested_params);

private:
    Config                   m_config;
    std::map<int, XpandNode> m_nodes_by_id;
    std::vector<std::string> m_health_urls;
    mxb::http::Async         m_http;
    mxb::Worker::DCId        m_delayed_http_check_id {0};
    long                     m_last_cluster_check {0};
    SERVER*                  m_pHub_server {nullptr};
    MYSQL*                   m_pHub_con {nullptr};
    sqlite3*                 m_pDb {nullptr};
    bool                     m_is_group_change {false};
    mxs::ConfigParameters    m_extra;

    std::vector<XpandServer*> m_bootstrap_servers;    /**< Configured servers */
    std::vector<XpandServer*> m_active_servers;        /**< Discovered servers */
    bool                      m_active_servers_changed {false};

    void configured_servers_updated(const std::vector<SERVER*>& servers) override;
};

class XpandServer : public mxs::MariaServer
{
public:
    XpandServer(SERVER* server, const SharedSettings& shared);
};

/*
 * Copyright (c) 2019 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2023-11-12
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */

#include "sql.hh"

SQL::SQL(MYSQL* mysql, const cdc::Server& server)
    : m_mysql(mysql)
    , m_server(server)
{
}

SQL::~SQL()
{
    mysql_free_result(m_res);
    mariadb_rpl_close(m_rpl);
    mysql_close(m_mysql);
}

std::pair<std::string, std::unique_ptr<SQL>> SQL::connect(const std::vector<cdc::Server>& servers,
                                                          int connect_timeout, int read_timeout)
{
    std::unique_ptr<SQL> rval;
    MYSQL* mysql = nullptr;
    std::string error;

    if (servers.empty())
    {
        error = "No servers defined";
    }

    for (const auto& server : servers)
    {
        if (!(mysql = mysql_init(nullptr)))
        {
            error = "Connection initialization failed";
            break;
        }

        mysql_optionsv(mysql, MYSQL_OPT_CONNECT_TIMEOUT, &connect_timeout);
        mysql_optionsv(mysql, MYSQL_OPT_READ_TIMEOUT, &read_timeout);

        if (!mysql_real_connect(mysql, server.host.c_str(), server.user.c_str(), server.password.c_str(),
                                nullptr, server.port, nullptr, 0))
        {
            error = "Connection creation failed: " + std::string(mysql_error(mysql));
            mysql_close(mysql);
            mysql = nullptr;
        }
        else
        {
            // Successful connection
            rval.reset(new SQL(mysql, server));
            error.clear();
            break;
        }
    }

    return {error, std::move(rval)};
}

bool SQL::query(const std::string& sql)
{
    if (m_res)
    {
        mysql_free_result(m_res);
        m_res = nullptr;
    }

    return mysql_query(m_mysql, sql.c_str()) == 0;
}

bool SQL::query(const std::vector<std::string>& sql)
{
    for (const auto& a : sql)
    {
        if (!query(a.c_str()))
        {
            return false;
        }
    }

    return true;
}

bool SQL::replicate(int server_id)
{
    if (!(m_rpl = mariadb_rpl_init(m_mysql)))
    {
        return false;
    }

    mariadb_rpl_optionsv(m_rpl, MARIADB_RPL_SERVER_ID, &server_id);

    if (mariadb_rpl_open(m_rpl))
    {
        return false;
    }

    return true;
}

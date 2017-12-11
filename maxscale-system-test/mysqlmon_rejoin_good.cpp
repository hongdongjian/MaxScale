/*
 * Copyright (c) 2016 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2020-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */

#include <vector>

#include "testconnections.h"
#include "mysqlmon_failover_common.cpp"

using std::string;
typedef std::vector<string> StringVector;

const char GTID_QUERY[] = "SELECT @@gtid_current_pos;";
const char GTID_FIELD[] = "@@gtid_current_pos";
const int bufsize = 512;
/**
 * Do inserts, check that results are as expected.
 *
 * @param test Test connections
 * @paran insert_count
 */
void generate_traffic_and_check(TestConnections& test, int insert_count)
{
    MYSQL *conn = test.maxscales->open_rwsplit_connection(0);
    const char INSERT[] = "INSERT INTO test.t1 VALUES (%d);";
    const char SELECT[] = "SELECT * FROM test.t1 ORDER BY id ASC;";
    for (int i = 0; i < insert_count; i++)
    {
        test.try_query(conn, INSERT, inserts++);
        timespec time;
        time.tv_sec = 0;
        time.tv_nsec = 100000000;
        nanosleep(&time, NULL);
    }

    mysql_query(conn, SELECT);
    MYSQL_RES *res = mysql_store_result(conn);
    test.assert(res != NULL, "Query did not return a result set");

    if (res)
    {
        MYSQL_ROW row;
        // Check all values, they should go from 0 to 'inserts'
        int expected_val = 0;
        while ((row = mysql_fetch_row(res)))
        {
            int value_read = strtol(row[0], NULL, 0);
            if (value_read != expected_val)
            {
                test.assert(false, "Query returned %d when %d was expected", value_read, expected_val);
                break;
            }
            expected_val++;
        }
        int num_rows = expected_val;
        test.assert(num_rows == inserts, "Query returned %d rows when %d rows were expected",
                    num_rows, inserts);
        mysql_free_result(res);
    }
    mysql_close(conn);
}

void print_gtids(TestConnections& test)
{
    MYSQL* maxconn = test.maxscales->open_rwsplit_connection(0);
    if (maxconn)
    {
        char result_tmp[bufsize];
        if (find_field(maxconn, GTID_QUERY, GTID_FIELD, result_tmp) == 0)
        {
            test.tprintf("MaxScale gtid: %s", result_tmp);
        }
    }
    mysql_close(maxconn);
    test.repl->connect();
    for (int i = 0; i < test.repl->N; i++)
    {
        char result_tmp[bufsize];
        if (find_field(test.repl->nodes[i], GTID_QUERY, GTID_FIELD, result_tmp) == 0)
        {
            test.tprintf("Node %d gtid: %s", i, result_tmp);
        }
    }
}

int main(int argc, char** argv)
{
    interactive = strcmp(argv[argc - 1], "interactive") == 0;
    TestConnections test(argc, argv);
    MYSQL* maxconn = test.maxscales->open_rwsplit_connection(0);

    // Set up test table
    basic_test(test);
    // Delete binlogs to sync gtid:s
    delete_slave_binlogs(test);
    char result_tmp[bufsize];
    // Advance gtid:s a bit to so gtid variables are updated.
    generate_traffic_and_check(test, 10);
    sleep(1);
    test.tprintf(LINE);
    print_gtids(test);
    get_input();

    test.tprintf("Stopping master and waiting for failover. Check that another server is promoted.");
    test.tprintf(LINE);
    const int old_master_id = get_master_server_id(test); // Read master id now before shutdown.
    const int master_index = test.repl->master;
    test.repl->stop_node(master_index);
    sleep(10);
    // Recreate maxscale session
    mysql_close(maxconn);
    maxconn = test.maxscales->open_rwsplit_connection(0);
    get_output(test);
    int master_id = get_master_server_id(test);
    test.tprintf(LINE);
    test.tprintf(PRINT_ID, master_id);
    const bool failover_ok = (master_id > 0 && master_id != old_master_id);
    test.assert(failover_ok, "Master did not change or no master detected.");
    string gtid_final;
    if (failover_ok)
    {
        test.tprintf("Sending more inserts.");
        generate_traffic_and_check(test, 5);
        sleep(1);
        if (find_field(maxconn, GTID_QUERY, GTID_FIELD, result_tmp) == 0)
        {
            gtid_final = result_tmp;
        }
        print_gtids(test);
        test.tprintf("Bringing old master back online. It should rejoin the cluster and catch up in events.");
        test.tprintf(LINE);

        test.repl->start_node(master_index, (char*) "");
        sleep(10);
        get_output(test);

        test.repl->connect();
        sleep(1);
        string gtid_old_master;
        if (find_field(test.repl->nodes[master_index], GTID_QUERY, GTID_FIELD, result_tmp) == 0)
        {
            gtid_old_master = result_tmp;
        }
        test.tprintf(LINE);
        print_gtids(test);
        test.tprintf(LINE);
        test.assert(gtid_final == gtid_old_master, "Old master did not successfully rejoin the cluster.");
        // Switch master back to server1 so last check is faster
        int ec;
        test.maxscales->ssh_node_output(0, "maxadmin call command mysqlmon switchover "
                                        "MySQL-Monitor server1 server2" , true, &ec);
        sleep(5); // Wait for monitor to update status
        get_output(test);
        master_id = get_master_server_id(test);
        test.assert(master_id == old_master_id, "Switchover back to server1 failed.");
    }
    else
    {
        test.repl->start_node(master_index, (char*) "");
        sleep(10);
    }

    test.repl->fix_replication();
    return test.global_result;
}

/**
 * MXS-3924: Failed session commands aren't retried
 */

#include <maxtest/testconnections.hh>

void do_test(TestConnections& test, Connection& c)
{
    std::thread thr(
        [&]() {
            sleep(3);
            test.log_printf("Blocking all nodes");
            test.repl->block_all_nodes();
            test.maxscale->wait_for_monitor(2);
            sleep(5);
            test.log_printf("Unblocking all nodes");
            test.repl->unblock_all_nodes();
            test.maxscale->wait_for_monitor(2);
            test.tprintf("thread done");
        });

    test.log_printf("Executing SELECT SLEEP");
    test.expect(c.query("SET @a=(SELECT SLEEP(10))"), "SET failed: %s", c.error());

    thr.join();

    test.log_printf("Executing SELECT 1");
    test.expect(c.query("SELECT 1"), "SELECT failed: %s", c.error());
}

void mxs4289(TestConnections& test, Connection& c)
{
    std::thread thr(
        [&]() {
        sleep(3);
        test.log_printf("Blocking first three nodes");
        for (int i = 0; i < 3; i++)
        {
            test.repl->block_node(i);
        }

        test.maxscale->wait_for_monitor(2);
        sleep(2);

        test.log_printf("Blocking final node");
        test.repl->block_node(3);
        test.maxscale->wait_for_monitor(2);
        sleep(5);

        test.log_printf("Unblocking all nodes");
        test.repl->unblock_all_nodes();
        test.maxscale->wait_for_monitor(2);
        test.tprintf("thread done");
    });
    test.expect(c.connect(), "Failed to connect: %s", c.error());
    test.expect(c.query("SET autocommit=0"), "SET autocommit=0 failed: %s", c.error());

    test.log_printf("Executing SELECT SLEEP");
    test.expect(c.query("SET @a=(SELECT SLEEP(10))"), "SET failed: %s", c.error());

    thr.join();

    test.log_printf("Executing SELECT 1");
    test.expect(c.query("SELECT 1"), "SELECT failed: %s", c.error());

    test.expect(c.query("COMMIT"), "COMMIT failed: %s", c.error());
}

int main(int argc, char** argv)
{
    TestConnections test(argc, argv);

    auto c = test.maxscale->rwsplit();
    c.set_timeout(60);
    test.expect(c.connect(), "Failed to connect: %s", c.error());

    test.log_printf("Default test");
    do_test(test, c);

    test.log_printf("Inside a transaction");
    test.expect(c.connect(), "Failed to connect: %s", c.error());
    test.expect(c.query("START TRANSACTION"), "START TRANSACTION failed: %s", c.error());
    do_test(test, c);
    test.expect(c.query("COMMIT"), "COMMIT failed: %s", c.error());

    test.log_printf("Inside a read-only transaction");
    test.expect(c.connect(), "Failed to connect: %s", c.error());
    test.expect(c.query("START TRANSACTION READ ONLY"), "START TRANSACTION READ ONLY failed: %s", c.error());
    do_test(test, c);
    test.expect(c.query("COMMIT"), "COMMIT failed: %s", c.error());

    test.log_printf("Autocommit disabled");
    test.expect(c.connect(), "Failed to connect: %s", c.error());
    test.expect(c.query("SET autocommit=0"), "SET autocommit=0 failed: %s", c.error());
    do_test(test, c);
    test.expect(c.query("COMMIT"), "COMMIT failed: %s", c.error());

    test.log_printf("MXS-4289: Retrying failing session command inside a transaction");
    mxs4289(test, c);

    return test.global_result;
}

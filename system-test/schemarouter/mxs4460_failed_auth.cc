#include <maxtest/testconnections.hh>

int main(int argc, char** argv)
{
    TestConnections test(argc, argv);

    test.check_maxctrl("call command mariadbmon reset-replication Monitor1 server1");
    test.check_maxctrl("call command mariadbmon reset-replication Monitor2 server3");
    test.maxscale->wait_for_monitor();

    auto c = test.repl->get_connection(2);
    c.connect();
    c.query("CREATE USER bob IDENTIFIED BY 'bob'");
    c.query("GRANT ALL ON *.* TO bob");

    using Clock = std::chrono::steady_clock;
    auto start = Clock::now();

    for (int i = 0; i < 1000 && Clock::now() - start < 30s && test.ok(); i++)
    {
        auto rws = test.maxscale->rwsplit(i % 2 == 0 ? "test" : "");
        rws.set_credentials("bob", "bob");
        test.expect(rws.connect(), "Failed to connect: %s", rws.error());
        test.expect(rws.query("SELECT 1"), "Failed to query: %s", rws.error());
    }

    c.query("DROP USER bob");

    test.repl->fix_replication();
    return test.global_result;
}
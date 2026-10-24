/* Fixture: C++ target exercising the C++ build path and virtual dispatch.
 *
 * Two things this checks that no C fixture can: that aether-cc links the C++
 * standard library while keeping the coverage runtime compiled as C, and that
 * a virtual call shows up as coverage (the indirect-call hook), since two
 * paths through the same call site are otherwise indistinguishable.
 *
 * The defect is an out-of-range vector access, which throws and terminates. */
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

struct Handler {
    virtual ~Handler() = default;
    virtual int handle(unsigned char n, std::vector<int> &v) = 0;
};

struct Reader : Handler {
    int handle(unsigned char n, std::vector<int> &v) override {
        return v.at(n);              /* known defect: n may exceed the size */
    }
};

struct Writer : Handler {
    int handle(unsigned char n, std::vector<int> &v) override {
        v.at(n) = 1;                 /* same defect on the write path */
        return 0;
    }
};

int main() {
    char buf[256];
    size_t n = fread(buf, 1, sizeof buf, stdin);
    std::string s(buf, n);
    if (s.size() < 5) return 0;
    if (s.rfind("CXX", 0) != 0) return 1;

    std::vector<int> v(16, 0);
    std::unique_ptr<Handler> h;
    /* Which implementation runs is decided by the input, so the two paths
     * differ only through the indirect call. */
    if (s[3] == 'R') h = std::make_unique<Reader>();
    else if (s[3] == 'W') h = std::make_unique<Writer>();
    else return 2;

    int r = h->handle(static_cast<unsigned char>(s[4]), v);
    printf("ok %d\n", r);
    return 0;
}

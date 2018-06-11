#include<optional>
#include<vector>

namespace ilia {
namespace util {

std::optional<std::vector<uint8_t>> ReadFile(const char *path);

}
}

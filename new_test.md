
```
#include <cstdlib>
#include <iostream>

int main() {
    std::cout << "Thông tin hệ thống (systeminfo):\n";
    system("systeminfo");

    std::cout << "\nThông tin IP (ipconfig /all):\n";
    system("ipconfig /all");

    return 0;
}
```

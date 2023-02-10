#include <windows.h>
#include <iostream>
#include <conio.h>
#include <ctime>

int main(int argc, char **argv)
{
    std::srand(std::time(NULL));
    int x, y;
    int sx, sy;
    while (1) {
        POINT xypos;
        GetCursorPos(&xypos);
        // std::cout << "X: " << xypos.x << "\tY: " << xypos.y << std::endl;
        // sx = (rand() % 2) == 0 ? 1 : -1;
        // sy = (rand() % 2) == 0 ? 1 : -1;
        // std::cout << sx << " " << sy << std::endl;
        // SetCursorPos(xypos.x + (rand() % 2) * sx, xypos.y - (rand() % 2) * sy);
        SetCursorPos(xypos.x + 1, xypos.y + 1);
        Sleep(0.5);
    }
}
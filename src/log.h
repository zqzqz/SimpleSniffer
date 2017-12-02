#ifndef LOG_H
#define LOG_H
#include <iostream>
#define LOG(msg) std::cout<<"("<<__FILE__<<":"<<__LINE__<<")"<<msg<<endl;
#endif // LOG_H

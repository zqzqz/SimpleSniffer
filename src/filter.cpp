#include "filter.h"

Filter::Filter()
{

}

Filter::~Filter()
{

}

/*
 * usage of commands
 * [-options] [data] ...
 * -p protocol / -s sourceIP / -d destinationIP / -sport sourcePort / -dport destinationPort
 * using regex to check syntax.
 */
bool Filter::checkCommand(QString command)
{
    //LOG(command.toLatin1().data());
    std::string pattern{ "([ ]*((-p[ ]+[a-zA-Z]+)|((-s|-d)[ ]+\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3})|((-sport|-dport)[ ]+\\d+))[ ]*)*" };
    std::regex re(pattern);
    return std::regex_match(command.toStdString(), re);
}

/*
 * load correct command to query structure
 * preparation for function filtrate.
 */
bool Filter::loadCommand(QString command)
{
    //LOG(command.toLatin1().data());
    query.clear();
    if (! checkCommand(command)) {
        return false;
    }
    std::string com = command.toStdString();
    std::size_t pos;
    pos = com.find("-p");
    if (pos<com.size()) query.insert(make_pair("-p", findWord(com, pos+2)));
    pos = com.find("-s");
    if (pos<com.size()) query.insert(make_pair("-s", findWord(com, pos+2)));
    pos = com.find("-d");
    if (pos<com.size()) query.insert(make_pair("-d", findWord(com, pos+2)));
    pos = com.find("-sport");
    if (pos<com.size()) query.insert(make_pair("-sport", findWord(com, pos+5)));
    pos = com.find("-dport");
    if (pos<com.size()) query.insert(make_pair("-dport", findWord(com, pos+5)));
    return true;
}

string Filter::findWord(string com, size_t pos)
{
    size_t beg = com.find_first_not_of(string(" "), pos);
    size_t end = com.find_first_of(string(" "), beg);
    if (end >= com.size()) end = com.find_first_of(string("\n"), beg);

    return com.substr(beg, end-beg);
}

void Filter::launchFilter(QListView *pListView) {
    //add code here
}


bool Filter::filtrate(QString command, QListView *pListView) {
    if (! loadCommand(command)) {
        return false;
    }
    launchFilter(pListView);
    return true;
}

void Filter::printQuery()
{
    LOG("test mode");
    std::cout<<"-p  "<<query.size()<<endl;
}

#include <iostream>
#include <fstream>
#include <regex>
#include <string>

void handle_imp_strings(const std::string& input_filename, const std::string& output_filename) {
    std::ifstream infile(input_filename);
    std::ofstream outfile(output_filename);
    std::string line;
    std::regex pattern(R"(__imp_[^:]*)"); // matches __imp_ up to but not including '('

    while (std::getline(infile, line)) {
        std::smatch match;
        std::string::const_iterator searchStart(line.cbegin());
        while (std::regex_search(searchStart, line.cend(), match, pattern)) {
            // Find the position of "("
            std::string line2 = match.str();
            size_t pos = line2.find('(');
            std::cout << pos << std::endl;
            if (pos != std::string::npos)
                // Erase from position of "(" to end
                line2.erase(pos);
            outfile << "PPC_FUNC_THROW(" << line2 << ");\n";
            searchStart = match.suffix().first;
        }
    }
}

int main() {
    handle_imp_strings("in.txt", "out.txt");
    return 0;
}

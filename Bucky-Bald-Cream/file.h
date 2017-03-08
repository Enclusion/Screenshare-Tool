#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <psapi.h>

#include <boost/optional.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>
#include <boost/crc.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/bind.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/uuid/sha1.hpp>
#include <boost/functional/hash.hpp> 


#include <iostream>
#include <memory>
#include <string>
#include <unordered_set>
#include <unordered_map>


bool HashMods(std::vector<std::string> hashes);
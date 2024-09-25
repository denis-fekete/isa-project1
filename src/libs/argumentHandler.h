/**
 * @file argumentHandler.h
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief //TODO:
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#ifndef ARGUMENT_HANLER_H
#define ARGUMENT_HANLER_H

// ----------------------------------------------------------------------------
//  Includes
// ----------------------------------------------------------------------------

#include "getopt.h"
#include "string.h"

#include "utils.h"
#include "buffer.h"
#include "programConfig.h"

// ----------------------------------------------------------------------------
//  Structures and enums
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
//  Functions
// ----------------------------------------------------------------------------

/**
 * @brief Handles program arguements and sets correct 
 * ProgramConfiguration (Config)
 * 
 * @param argc 
 * @param argv 
 * @param config pointer to ProgramConfiguration (Config)
 */
void argumentHandler(int argc, char* argv[], Config* config);

/**
 * @brief Prints help menu when user inputs /help command 
 */
void printCliHelpMenu(const char* executableName);

#endif /*ARGUMENT_HANLER_H*/
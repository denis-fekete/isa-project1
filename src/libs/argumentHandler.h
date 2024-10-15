/**
 * @file argumentHandler.h
 * @author Denis Fekete (xfeket01@vutbr.cz)
 * @brief Header file containing argument handling functions
 * 
 * @copyright Copyright (c) 2024
 * 
 */
#ifndef ARGUMENT_HANDLER_H
#define ARGUMENT_HANDLER_H

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
 * @brief Handles program arguments and sets correct 
 * ProgramConfiguration (Config)
 * 
 * @param argc 
 * @param argv 
 * @param config Pointer to the Config structure that holds program settings to 
 * set desired behaviour of program and also allocated all allocated variables
 */
void argumentHandler(int argc, char* argv[], Config* config);

/**
 * @brief Prints help menu when user inputs /help command 
 */
void printCliHelpMenu(const char* executableName);

#endif /*ARGUMENT_HANDLER_H*/
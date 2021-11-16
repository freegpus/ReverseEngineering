#TODO write a description for this script
#Removes all functions with a malloc before the function call
#@author Eric 
#@category Examples.Python
#@keybinding 
#@menupath 
#@toolbar 
from ghidra.app.script import GhidraScript
from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileResults
from ghidra.program.model.pcode import HighParam, PcodeOp, PcodeOpAST
from ghidra.program.model.address import GenericAddress
from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.program.model.address import Address
from ghidra.program.model.address import AddressSet
import logging
import struct
from java.awt import Color


debug = True
# debug = False
process_is_64bit = False

# Init Default Logger
logger = logging.getLogger('Default_logger')
logger.setLevel(logging.INFO)
consolehandler = logging.StreamHandler()
console_format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
consolehandler.setFormatter(console_format)
logger.addHandler(consolehandler)

if debug:
    logger.setLevel(logging.DEBUG)

#global variables
refList = []
addresses = []
parent_functions = []
parent_function_params = []
vuln_parent = []
vuln_params = []
malloc_list = []
branches_found = []
malloc_from_list = []
strlen_from_list = []
service = state.getTool().getService(ColorizingService)
addresses_to_color = AddressSet()

def find_malloc(func_addr, fun_obj):
    currentInstr = getInstructionContaining(func_addr)
    #print("In a new function!!")
    while(getFunctionContaining(currentInstr.getAddress()) == fun_obj):
        search_string = currentInstr.toString()
        #looking for all the bl instructions then comparing the address
        #of that instruction to the addresses of all the mallocs
        if search_string.find('bl') != -1:
            
            branches_found.append(str(currentInstr.getAddress()))
            
            if str(currentInstr.getAddress()) in malloc_from_list:
                #print("Malloc found")
                return 1                  

        currentInstr = currentInstr.getNext()

def find_strlen(func_addr, fun_obj):
    currentInstr = getInstructionContaining(func_addr)
    #print("In a new function!!")
    while(getFunctionContaining(currentInstr.getAddress()) == fun_obj):
        search_string = currentInstr.toString()
        #looking for all the bl instructions then comparing the address
        #of that instruction to the addresses of all the mallocs
        if search_string.find('bl') != -1:
            
            branches_found.append(str(currentInstr.getAddress()))
            
            if str(currentInstr.getAddress()) in strlen_from_list:
                if (currentInstr.getNext().toString().find('add') != -1 or currentInstr.getNext().toString().find('or') != -1):
                    #print("Safe strlen found: {}".format(currentInstr.getNext().toString()))
                    return 1                  

        currentInstr = currentInstr.getNext()
    

def find_params(function, address, color_address):
    target_func = getGlobalFunctions(str(function))
    if len(target_func) == 0:
        return
    else:
        funObj = target_func[0]
        
        fun_addr = funObj.getEntryPoint()
        if (find_malloc(fun_addr, funObj) == 1 and find_strlen(fun_addr, funObj) == 1):
            return
        else:
            string_convert = str(funObj.getParameters())
            string_convert = string_convert[46:]
            if(string_convert.find('parm') != -1 or string_convert.find('param') != -1):
                vuln_parent.append(funObj)
                vuln_params.append(funObj.getParameters())
                print("Function address at 0x{:016x} is called by {} and is potentially vulnerable with these parent parameters: {}".format(address, funObj, string_convert))
                print("")
                addresses_to_color.add(color_address)


if __name__ == '__main__':
    search_functions = None
    function_name = askString("Input function name you would like to find vulnerability for", "Please input the function name. Ex: strcpy")
    target_function = getGlobalFunctions(function_name)
    if len(target_function) == 0:
        print("Can't find function provided: {}".format(function_name))
        exit()
    else:
        funObj = target_function[0]
        #print(funObj.getParameters())

    funObjAddr = funObj.getEntryPoint()
    print("Address of the leaf function is {}".format(funObjAddr))

    refList = list(getReferencesTo(funObjAddr))

    malloc_func = getGlobalFunctions("malloc")
    malloc_func_spec = malloc_func[0]
    malloc_list = list(getReferencesTo(malloc_func_spec.getEntryPoint()))
    for ref in malloc_list:
        malloc_from_list.append(str(ref.getFromAddress()))

    strlen_func = getGlobalFunctions("strlen")
    strlen_func_spec = strlen_func[0]
    strlen_list = list(getReferencesTo(strlen_func_spec.getEntryPoint()))
    for ref in malloc_list:
        strlen_from_list.append(str(ref.getFromAddress()))
    
    
    if len(refList) > 0:
        #parse_functions(target_function)
        print("{} references to function {}".format(len(refList), funObj.getName()))
        for ref in refList:

            find_params(getFunctionContaining(ref.getFromAddress()), ref.getFromAddress().getOffset(), ref.getFromAddress())

        setBackgroundColor(addresses_to_color, Color(100, 100, 200))

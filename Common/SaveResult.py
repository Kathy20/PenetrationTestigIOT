###############################################################
#             Instituto Tecnologico de Costa Rica             #
#                  Maestria en Computacion                    #
#                                                             #
#   Estudiante                                                #
#   Kathy Brenes Guerrero                                     #
#                                                             #
#   Fecha                                                     # 
#   Marzo 2021                                                #
###############################################################
import csv

def write_file(file_name, results):
    # Writing to CSV file
    with open(file_name, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(results)
    print("Writting to results_" + file_name + ".csv")
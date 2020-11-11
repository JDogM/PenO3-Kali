def shift_right(row,nb_steps):
    for i in range(nb_steps):
        row = [row[-1]] + row[0:-1]
        
    return row

def shift_matrix_row(matrix):
    for i in range(1,len(matrix)):
        matrix[i] = shift_right(matrix[i],i)
        
    return matrix



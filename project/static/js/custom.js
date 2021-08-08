/*
taken from https://www.w3schools.com/howto/howto_js_filter_table.asp
function is used to filter table (find a specific resource from the list of resources in a table)
the field names are set in the file _formhelpers.html which has macros one of which is 
used to create record tables
*/
function filter() {
    // Declare variables
    var input, filter, table, tr, td, i, txtValue;
    input = document.getElementById("filter");
    filter = input.value.toUpperCase();
    table = document.getElementById("tbl-records");
    tr = table.getElementsByTagName("tr");
    

    // Loop through all table rows, and hide those who don't match the search query
    for (i = 0; i < tr.length; i++) {
        td = tr[i].getElementsByTagName("td")[0]; //the first td element of each tr is the resourcename data
        if (td) {
            txtValue = td.textContent || td.innerText;
            if (txtValue.toUpperCase().indexOf(filter) > -1) {
                tr[i].style.display = "";
            } else {
                tr[i].style.display = "none";
            }
        }
    }
}

// hides a particular column (0 is the first column, 1 is the 2nd, etc)
function hideColumn(column_number=0, action=null) {
    if (action) {
        var table = $("#tbl-records")
        var tr = $("#tbl-records").find("tr")
        tr.each(function(index, item) {
            cols = $(this).children()
            if (column_number < cols.length) {
                if (action == 'hide') {
                    $(cols[column_number]).fadeOut();
                }
                else {
                    $(cols[column_number]).fadeIn();
                }
                
            }

        });
    }
}

// unhide all <td> and <th>
function showAllColumns() {
    var table = $("#tbl-records")
    var tr = $("#tbl-records").find("tr") // collection of all <tr> elements
    tr.each(function(index, item) {         // for each <tr> element
        cols = $(this).children()           // collection of all columns
        cols.each(function(index, item) {
            $(item).fadeIn();
        });
    });
}

/*
idea is taken https://www.w3schools.com/howto/howto_js_navbar_sticky.asp but re-written to
make it work for this page.

the function makes the obj argument stick to the top after scrolling a certain distance.

scrolldistance: how much to scroll before the object becomes sticky. Need to scroll by the distance
between the top of the search box and the bottom of the navbar

stickyObj: the object to apply stickyness to

stickyTop: the position from the top at which the object sticks. This is basically the height of the 
navbar since the object will stick just below the navbar which is the first object of the page.

extraSpace: when the object becomes sticky, it creates a gap on the page which other non-positioned fill.
so we must preserve the distance between the table (element below the sticky object) 
and the element above (alert box) the sticky object.

*/
function sticky(scrolldistance, stickyObj, stickyTop, extraSpace) {
    table = $("#tbl-records");
    
    if ($(document).scrollTop() >= scrolldistance) {
        stickyObj.addClass("sticky");
        stickyObj.css({
            "top": stickyTop + "px"
        });
        table.css({
            "margin-top": extraSpace + 0 + "px",   //16 (now 0): margin-bottom of the alert box = 1rem
        })

        
    } else {
        stickyObj.removeClass("sticky");
        table.css({
            "margin-top": 0 + "px",
        });
        stickyObj.css({
            "top": "initial"
        });
    }
}


import flet as ft
import finder


# def start_searching(input_path, output_path, ssid):
#     print(input_path)
#     print(output_path)
#     print(ssid)
# find = finder.Finder()
# find.parse_data(input_path)
# find.search(ssid)
# find.save_to_file(output_path)
# find.draw_graph()


def main(page: ft.Page):
    page.title = "Drone finder"
    input_path = ft.TextField(label="Enter path to input data file", width=300, height=35, text_size=14)
    output_path = ft.TextField(label="Enter path to output file", value="", width=300, height=35, text_size=14)
    ssid = ft.TextField(label="Enter ssid for search", value="", width=300, height=35, text_size=14)

    def start_searching(e):
        _finder = finder.Finder()
        _finder.parse_data(input_path.value)  # ./data/frames_phy.log
        _finder.search([ssid.value, ''][ssid.value == ''])
        _finder.save_to_file([output_path.value, './results/test'][output_path.value == ''])
        _finder.draw_graph()

    # page.vertical_alignment = ft.MainAxisAlignment.CENTER

    # def minus_click(e):
    #     txt_number.value = str(int(txt_number.value) - 1)
    #     page.update()

    page.add(
        ft.Column(
            [
                ft.Row([ft.Text("Path to input data file", size=14), input_path], spacing=10),
                ft.Row([ft.Text("Path to output data file", size=14), output_path], spacing=10),
                ft.Row([ft.Text("SSID", size=14), ssid], spacing=10),
                ft.ElevatedButton(text="Start Searching", on_click=start_searching)
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=20
        )
    )


ft.app(main)

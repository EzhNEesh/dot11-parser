import flet as ft

from .command_handler.gui_handler import Handler
from .networking.network_graph import NetworkGraph


def main(page: ft.Page):
    handler = Handler()
    network_graph = NetworkGraph()
    page.title = "Drone detector"
    action_container = ft.Container()

    def close_dlg(e):
        dlg_modal.open = False
        page.update()

    def open_dlg(message):
        dlg_modal.content = ft.Text(message)
        page.dialog = dlg_modal
        dlg_modal.open = True
        page.update()

    def update_find_button(e):
        if rg_models.value is not None and (rg_models.value != 'ssid' or rg_models.value == 'ssid' and len(ssid.value))\
                and len(input_path.value):
            find_button.disabled = False
        else:
            find_button.disabled = True
        action_container.update()

    def update_retrain_button(e):
        if (len(paths_to_datas.value) and len(drone_addresses.value)
                and rg_models.value is not None and rg_models.value != 'ssid'):
            retrain_button.disabled = False
        else:
            retrain_button.disabled = True
        action_container.update()

    def find_drones(e):
        try:
            dot11_dataframe = handler.read_frames(input_path.value)
        except FileNotFoundError:
            open_dlg(f'File or directory {input_path.value} does not exist')
            return
        except IndexError:
            open_dlg(f'Invalid data')
            return
        prediction = []
        macs = []
        control_devices = []
        if not ssid.disabled:
            macs, control_devices = handler.get_drones_by_ssid(dot11_dataframe, ssid.value)
            prediction = [1] * len(macs)
        else:
            prediction, macs, control_devices = handler.predict(rg_models.value, dot11_dataframe)
        network_graph.draw_graph(dot11_dataframe, prediction, macs, control_devices)
        if len(output_path.value):
            handler.save_to_file(dot11_dataframe, macs, output_path.value)
        else:
            handler.save_to_file(dot11_dataframe, macs)

    def retrain_model(e):
        try:
            handler.retrain_model(rg_models.value, paths_to_datas.value, drone_addresses.value)
        except ValueError:
            open_dlg(f'File does not exits or invalid data')
            return
        except TypeError:
            open_dlg(f'Invalid data')
            return

    def add_predict_to_page():
        action_container.content = ft.Column(
            [
                ft.Row([ft.Text("Path to input data file*", size=14), input_path], spacing=10),
                ft.Row([ft.Text("Path to output data file", size=14), output_path], spacing=10),
                ft.Row([ft.Text("Select a search method:", size=14)], spacing=10),
                rg_models,
                ft.Row([ft.Text("SSID", size=14), ssid], spacing=10),
                find_button
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=20)
        ssid_radio.visible = True
        action_container.update()

    def add_retrain_to_page():
        action_container.content = ft.Column(
            [
                paths_to_datas,
                drone_addresses,
                rg_models,
                retrain_button
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=20)
        ssid_radio.visible = False
        action_container.update()

    def rg_model_changed(e):
        if e.control.value == 'ssid':
            ssid.disabled = False
        else:
            ssid.disabled = True
        update_find_button(e)
        update_retrain_button(e)

    def rg_action_changed(e):
        match e.control.value:
            case 'Find':
                add_predict_to_page()
            case 'Retrain':
                add_retrain_to_page()
            case 'Incremental train':
                pass

    input_path = ft.TextField(label="Enter path to input data file",
                              width=300, height=35,
                              text_size=14, on_change=update_find_button)
    output_path = ft.TextField(label="Enter path to output file", value="", width=300, height=35, text_size=14)

    ssid = ft.TextField(label="Enter ssid for search", value="",
                        width=300, height=35, text_size=14,
                        disabled=True, on_change=update_find_button)
    ssid_radio = ft.Radio(value="ssid", label="By ssid", visible=False)

    paths_to_datas = ft.TextField(label="Enter path to directory with frames files*",
                                  on_change=update_retrain_button)
    drone_addresses = ft.TextField(label="Enter path to file with MAC-addresses of drones*",
                                   on_change=update_retrain_button)
    rg_models = ft.RadioGroup(content=ft.Column([
        ft.Radio(value="knn", label="K-Neighbors Classifier"),
        ft.Radio(value="logistic_regression", label="Logistic Regression"),
        ft.Radio(value="decision_tree", label="Decision Tree"),
        ssid_radio
    ]), on_change=rg_model_changed)

    rg = ft.RadioGroup(content=ft.Column([
        ft.Radio(value="Find", label="Find"),
        ft.Radio(value="Retrain", label="Retrain"),
        ft.Radio(value="Incremental train", label="Incremental train")
    ]), on_change=rg_action_changed)
    page.add(rg)
    page.add(action_container)
    find_button = ft.ElevatedButton(text="Start Searching", on_click=find_drones, disabled=True)
    retrain_button = ft.ElevatedButton(text="Retrain", on_click=retrain_model, disabled=True)

    dlg_modal = ft.AlertDialog(
        modal=True,
        title=ft.Text("Something went wrong"),
        content=ft.Text(""),
        actions=[
            ft.TextButton("OK", on_click=close_dlg),
        ],
        actions_alignment=ft.MainAxisAlignment.END,
        on_dismiss=lambda e: print("Modal dialog dismissed!"),
    )


ft.app(main)

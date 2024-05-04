import flet as ft

from .command_handler.gui_handler import Handler
from .networking.network_graph import NetworkGraph


def main(page: ft.Page):
    handler = Handler()
    network_graph = NetworkGraph()
    page.title = "Drone finder"
    action_container = ft.Container()

    input_path = ft.TextField(label="Enter path to input data file", width=300, height=35, text_size=14)
    output_path = ft.TextField(label="Enter path to output file", value="", width=300, height=35, text_size=14)
    ssid = ft.TextField(label="Enter ssid for search", value="", width=300, height=35, text_size=14)

    paths_to_datas = ft.TextField(label="Enter paths to data files with line break", multiline=True)
    drone_addresses = ft.TextField(label="Enter MAC addresses with line break", multiline=True)
    rg_models = ft.RadioGroup(content=ft.Column([
        ft.Radio(value="knn", label="K-Neighbors Classifier"),
        ft.Radio(value="logistic_regression", label="Logistic Regression"),
        ft.Radio(value="decision_tree", label="Decision Tree")]))

    def find_drones(e):
        dot11_dataframe = handler.read_frames(input_path.value)
        prediction = []
        macs = []
        control_devices = []
        if ssid.value:
            macs, control_devices = handler.get_drones_by_ssid(dot11_dataframe, ssid.value)
            prediction = [1] * len(macs)
        else:
            prediction, macs, control_devices = handler.predict(rg_models.value, dot11_dataframe)
        network_graph.draw_graph(dot11_dataframe, prediction, macs, control_devices)
        if output_path.value:
            handler.save_to_file(dot11_dataframe, macs, output_path.value)
        else:
            handler.save_to_file(dot11_dataframe, macs)

    def retrain_model(e):
        paths = paths_to_datas.value.split('\n')
        drones = drone_addresses.value.split('\n')
        handler.retrain_model(rg_models.value, paths, drones)

    def add_predict_to_page():
        action_container.content = ft.Column(
            [
                ft.Row([ft.Text("Path to input data file", size=14), input_path], spacing=10),
                ft.Row([ft.Text("Path to output data file", size=14), output_path], spacing=10),
                ft.Row([ft.Text("SSID", size=14), ssid], spacing=10),
                rg_models,
                ft.ElevatedButton(text="Start Searching", on_click=find_drones)
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=20)
        action_container.update()

    def add_retrain_to_page():
        action_container.content = ft.Column(
            [
                paths_to_datas,
                drone_addresses,
                rg_models,
                ft.ElevatedButton(text="Retrain", on_click=retrain_model)
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=20)
        action_container.update()

    def radiogroup_changed(e):
        match e.control.value:
            case 'Predict':
                add_predict_to_page()
            case 'Retrain':
                add_retrain_to_page()
            case 'Incremental train':
                pass
        # page.update()

    # page.vertical_alignment = ft.MainAxisAlignment.CENTER

    # def minus_click(e):
    #     txt_number.value = str(int(txt_number.value) - 1)
    #     page.update()

    rg = ft.RadioGroup(content=ft.Column([
        ft.Radio(value="Predict", label="Predict"),
        ft.Radio(value="Retrain", label="Retrain"),
        ft.Radio(value="Incremental train", label="Incremental train")]), on_change=radiogroup_changed)
    page.add(rg)
    page.add(action_container)


ft.app(main)

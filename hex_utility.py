import sublime
import sublime_plugin
from random import randrange
from os.path import basename, dirname, exists
from struct import unpack
import re

HIGHLIGHT_SCOPE = "string"
HIGHLIGHT_ICON = "dot"
HIGHLIGHT_STYLE = "solid"
ADDRESS_OFFSET = 11
ASCII_OFFSET = 3
MS_HIGHLIGHT_DELAY = 500
BITS_PER_BYTE = 8

hv_settings = sublime.load_settings('hex_viewer.sublime-settings')
hv_inspector_enable = hv_settings.get("inspector", False)
hv_endianness = hv_settings.get("inspector_endian", "little")


def is_enabled():
    window = sublime.active_window()
    if window == None:
        return False
    view = window.active_view()
    if view == None:
        return False
    syntax = view.settings().get('syntax')
    language = basename(syntax).replace('.tmLanguage', '').lower() if syntax != None else "plain text"
    return (language == "hex")


def get_byte_count(start, end, group_size):
    return int((end - start - 1) / (group_size * 2 + 1)) * int(group_size) + int(((end - start - 1) % (group_size * 2 + 1)) / 2 + 1)


def get_hex_range(line, group_size, bytes_wide):
    hex_chars = int((group_size * 2) * bytes_wide / (group_size) + bytes_wide / (group_size)) - 1
    return sublime.Region(
        line.begin() + ADDRESS_OFFSET,
        line.begin() + ADDRESS_OFFSET + hex_chars
    )


def ascii_to_hex_col(col, index, group_size):
    #   Calculate byte number              Account for address
    #
    # current_char   wanted_byte
    # ------------ = -----------  => wanted_byte + offset = start_column
    #  total_chars   total_bytes
    #
    start_column = int(ADDRESS_OFFSET + (group_size * 2) * index / (group_size) + index / (group_size))
    # Convert byte column position to test point
    return start_column


def adjust_hex_sel(view, start, end, group_size):
    bytes = 0
    size = end - start
    if view.score_selector(start, 'raw.nibble.upper') == 0:
        if view.score_selector(start, 'raw.nibble.lower'):
            start -= 1
        elif view.score_selector(start + 1, 'raw.nibble.upper') and size > 0:
            start += 1
        else:
            start = None
    # Adjust ending of selection to end of last selected byte
    if size == 0 and start != None:
        end = start + 1
        bytes = 1
    elif view.score_selector(end, 'raw.nibble.lower') == 0:
        if view.score_selector(end - 1, 'raw.nibble.lower'):
            end -= 1
        else:
            end -= 2
    if start != None and end != None:
        bytes = get_byte_count(start, end, group_size)
    return start, end, bytes


def underline(selected_bytes):
    # Convert to empty regions
    new_regions = []
    for region in selected_bytes:
        start = region.begin()
        end = region.end()
        while start < end:
            new_regions.append(sublime.Region(start))
            start += 1
    return new_regions


class HexUtilityListenerCommand(sublime_plugin.EventListener):
    def check_debounce(self, debounce_id):
        if self.debounce_id == debounce_id:
            sublime.active_window().run_command('hex_nav')
            self.debounce_id = 0

    def debounce(self):
        # Check if debunce not currently active, or if of same type,
        # but let edit override selection for undos
        debounce_id = randrange(1, 999999)
        self.debounce_id = debounce_id
        sublime.set_timeout(
            lambda: self.check_debounce(debounce_id=debounce_id),
            MS_HIGHLIGHT_DELAY
        )

    def on_selection_modified(self, view):
        self.debounce()


class HexNavCommand(sublime_plugin.WindowCommand):
    def init(self):
        init_status = False
        self.address_done = False
        self.total_bytes = 0
        self.address = []
        self.selected_bytes = []

        # Get Seetings from settings file
        group_size = self.view.settings().get("hex_viewer_bits", None)
        self.inspector_enabled = hv_inspector_enable
        self.bytes_wide = self.view.settings().get("hex_viewer_actual_bytes", None)
        self.highlight_scope = hv_settings.get("highlight_scope", HIGHLIGHT_SCOPE)
        self.highlight_icon = hv_settings.get("highlight_icon", HIGHLIGHT_ICON)
        style = hv_settings.get("highlight_style", HIGHLIGHT_STYLE)

        # Process highlight style
        self.highlight_style = 0
        if style == "outline":
            self.highlight_style = sublime.DRAW_OUTLINED
        elif style == "none":
            self.highlight_style = sublime.HIDDEN
        elif style == "underline":
            self.highlight_style = sublime.DRAW_EMPTY_AS_OVERWRITE

        #Process hex grouping
        if group_size != None and self.bytes_wide != None:
            self.group_size = group_size / BITS_PER_BYTE
            init_status = True
        return init_status

    def is_enabled(self):
        return is_enabled()

    def get_address(self, start, bytes, line):
        lines = line
        align_to_address_offset = 2
        add_start = lines * self.bytes_wide + start - align_to_address_offset
        add_end = add_start + bytes - 1
        length = len(self.address)
        if length == 0:
            # Add first address group
            multi_byte = -1 if add_start == add_end else add_end
            self.address.append(add_start)
            self.address.append(multi_byte)
        elif (
            (self.address[1] == -1 and self.address[0] + 1 == add_start) or
            (self.address[1] != -1 and self.address[1] + 1 == add_start)
        ):
            # Update end address
            self.address[1] = add_end
        else:
            # Stop getting adresses if bytes are not consecutive
            self.address_done = True

    def display_address(self):
        count = ''
        if self.total_bytes == 0:
            self.view.set_status('hex_address', "Address: None")
            return
        # Display number of bytes whose address is not displayed
        if self.address_done:
            delta = 1 if self.address[1] == -1 else self.address[1] - self.address[0] + 1
            counted_bytes = self.total_bytes - delta
            if counted_bytes > 0:
                count = " [+" + str(counted_bytes) + " bytes]"
        # Display adresses
        status = "Address: "
        if self.address[1] == -1:
            status += ("0x%08x" % self.address[0]) + count
        else:
            status += ("0x%08x" % self.address[0]) + "-" + ("0x%08x" % self.address[1]) + count
        self.view.set_status('hex_address', status)

    def display_total_bytes(self):
        # Display total hex bytes
        self.view.set_status('hex_total_bytes', "Total Bytes: " + str(self.total_bytes))

    def hex_selection(self, start, bytes, first_pos):
        row, column = self.view.rowcol(first_pos)
        column = ascii_to_hex_col(column, start, self.group_size)
        hex_pos = self.view.text_point(row, column)

        # Log first byte
        if self.first_all == -1:
            self.first_all = hex_pos

         # Traverse row finding the specified bytes
        highlight_start = -1
        byte_count = bytes
        while byte_count:
            # Byte rising edge
            if self.view.score_selector(hex_pos, 'raw.nibble.upper'):
                if highlight_start == -1:
                    highlight_start = hex_pos
                hex_pos += 2
                byte_count -= 1
                # End of selection
                if byte_count == 0:
                    self.selected_bytes.append(sublime.Region(highlight_start, hex_pos))
            else:
                # Byte group falling edge
                self.selected_bytes.append(sublime.Region(highlight_start, hex_pos))
                hex_pos += 1
                highlight_start = -1
        # Log address
        if bytes and not self.address_done:
            self.get_address(start + 2, bytes, row)

    def ascii_to_hex(self, sel):
        view = self.view
        start = sel.begin()
        end = sel.end()
        bytes = 0
        ascii_range = view.extract_scope(sel.begin())

        # Determine if selection is within ascii range
        if start >= ascii_range.begin() and end <= ascii_range.end() + 1:
            # Single char selection
            if sel.size() == 0:
                bytes = 1
                self.selected_bytes.append(sublime.Region(start, end + 1))
            else:
                # Multi char selection
                bytes = end - start
                self.selected_bytes.append(sublime.Region(start, end))
            self.total_bytes += bytes
            # Highlight hex values
            self.hex_selection(start - ascii_range.begin(), bytes, start)

    def hex_to_ascii(self, sel):
        view = self.view
        start = sel.begin()
        end = sel.end()

        # Get range of hex data
        line = view.line(start)
        hex_range = get_hex_range(line, self.group_size, self.bytes_wide)

        # Determine if selection is within hex range
        if start >= hex_range.begin() and end <= hex_range.end():
            # Adjust beginning of selection to begining of first selected byte
            start, end, bytes = adjust_hex_sel(view, start, end, self.group_size)

            # Highlight hex values and their ascii chars
            if bytes != 0:
                self.total_bytes += bytes
                # Zero based byte number
                start_byte = get_byte_count(hex_range.begin(), start + 2, self.group_size) - 1
                self.hex_selection(start_byte, bytes, start)

                # Highlight Ascii
                ascii_start = hex_range.end() + ASCII_OFFSET + start_byte
                ascii_end = ascii_start + bytes
                self.selected_bytes.append(sublime.Region(ascii_start, ascii_end))

    def get_highlights(self):
        self.first_all = -1
        for sel in self.view.sel():
            if self.view.score_selector(sel.begin(), 'comment'):
                self.ascii_to_hex(sel)
            else:
                self.hex_to_ascii(sel)

    def run(self):
        view = self.window.active_view()
        self.view = view

        if not self.init():
            return

        self.get_highlights()

        # Show inspector panel
        if self.inspector_enabled:
            reset = False if self.total_bytes == 1 else True
            self.window.run_command(
                'hex_inspector',
                {'first_byte': self.first_all, 'reset': reset, 'bytes_wide': self.bytes_wide}
            )

        # Highlight selected regions
        if self.highlight_style == sublime.DRAW_EMPTY_AS_OVERWRITE:
            self.selected_bytes = underline(self.selected_bytes)
        view.add_regions(
            "hex_view",
            self.selected_bytes,
            self.highlight_scope,
            self.highlight_icon,
            self.highlight_style
        )
        # Display selected byte addresses and total bytes selected
        self.display_address()
        self.display_total_bytes()


class HexShowInspectorCommand(sublime_plugin.WindowCommand):
    def is_enabled(self):
        return is_enabled() and hv_inspector_enable

    def run(self):
        # Setup inspector window
        view = self.window.get_output_panel('hex_viewer_inspector')
        view.set_syntax_file("Packages/HexViewer/HexInspect.tmLanguage")
        view.settings().set("draw_white_space", "none")
        view.settings().set("draw_indent_guides", False)
        view.settings().set("gutter", "none")
        view.settings().set("line_numbers", False)
        # Show
        self.window.run_command("show_panel", {"panel": "output.hex_viewer_inspector"})
        self.window.run_command("hex_inspector", {"reset": True})


class HexHideInspectorCommand(sublime_plugin.WindowCommand):
    def is_enabled(self):
        return is_enabled() and hv_inspector_enable

    def run(self):
        self.window.run_command("hide_panel", {"panel": "output.hex_viewer_inspector"})


class HexToggleInspectorEndiannessCommand(sublime_plugin.WindowCommand):
    def is_enabled(self):
        return is_enabled() and hv_inspector_enable

    def run(self):
        global hv_endianness
        hv_endianness = "big" if hv_endianness == "little" else "little"
        self.window.run_command('hex_nav')


class HexInspectorCommand(sublime_plugin.WindowCommand):
    def get_bytes(self, start, bytes_wide):
        bytes = self.view.substr(sublime.Region(start, start + 2))
        byte64 = None
        byte32 = None
        byte16 = None
        byte8 = None
        start += 2
        size = self.view.size()
        count = 1
        group_divide = 1
        address = 12
        ascii_divide = group_divide + bytes_wide + address + 1
        target_bytes = 8

        # Look for 64 bit worth of bytes
        while start < size and count < target_bytes:
            # Check if sitting on first nibble
            if self.view.score_selector(start, 'raw.nibble.upper'):
                bytes += self.view.substr(sublime.Region(start, start + 2))
                count += 1
                start += 2
            else:
                # Must be at byte group falling edge; try and step over divider
                start += group_divide
                if start < size and self.view.score_selector(start, 'raw.nibble.upper'):
                    bytes += self.view.substr(sublime.Region(start, start + 2))
                    count += 1
                    start += 2
                # Must be at line end; try and step to next line
                else:
                    start += ascii_divide
                    if start < size and self.view.score_selector(start, 'raw.nibble.upper'):
                        bytes += self.view.substr(sublime.Region(start, start + 2))
                        count += 1
                        start += 2
                    else:
                        # No more bytes to check
                        break

        byte8 = bytes[0:2]
        if count > 1:
            byte16 = bytes[0:4]
        if count > 3:
            byte32 = bytes[0:8]
        if count > 7:
            byte64 = bytes[0:16]
        return byte8, byte16, byte32, byte64

    def display(self, view, byte8, bytes16, bytes32, bytes64):
        item_dec = "%-12s:  %-14d"
        item_str = "%-12s:  %-14s"
        item_float = "%-12s:  %-14e"
        item_double = "%-12s:  %-14e"
        nl = "\n"
        endian = ">" if self.endian == "big" else "<"
        i_buffer = "%28s:%-28s" % ("Hex Inspector ", (" Big Endian" if self.endian == "big" else " Little Endian")) + nl
        if byte8 != None:
            i_buffer += item_dec * 2 % (
                "byte", unpack(endian + "B", byte8.decode("hex"))[0],
                "short", unpack(endian + "b", byte8.decode("hex"))[0]
            ) + nl
        else:
            i_buffer += item_str * 2 % (
                "byte", "--",
                "short", "--"
            ) + nl
        if bytes16 != None:
            i_buffer += item_dec * 2 % (
                "word", unpack(endian + "H", bytes16.decode("hex"))[0],
                "int", unpack(endian + "h", bytes16.decode("hex"))[0]
            ) + nl
        else:
            i_buffer += item_str * 2 % (
                "word", "--",
                "int", "--"
            ) + nl
        if bytes32 != None:
            i_buffer += item_dec * 2 % (
                "dword", unpack(endian + "I", bytes32.decode("hex"))[0],
                "longint", unpack(endian + "i", bytes32.decode("hex"))[0]
            ) + nl
        else:
            i_buffer += item_str * 2 % (
                "dword", "--",
                "longint", "--"
            ) + nl
        if bytes32 != None:
            i_buffer += item_float % (
                "float", unpack(endian + "f", bytes32.decode('hex'))[0]
            )
        else:
            i_buffer += item_str % ("float", "--")
        if bytes64 != None:
            i_buffer += item_double % (
                "double", unpack(endian + "d", bytes64.decode('hex'))[0]
            ) + nl
        else:
            i_buffer += item_str % ("double", "--") + nl
        if byte8 != None:
            i_buffer += item_str % ("binary", '{0:08b}'.format(unpack(endian + "B", byte8.decode("hex"))[0])) + nl
        else:
            i_buffer += item_str % ("binary", "--") + nl

        # Update content
        view.set_read_only(False)
        edit = view.begin_edit()
        view.replace(edit, sublime.Region(0, view.size()), i_buffer)
        view.end_edit(edit)
        view.set_read_only(True)
        view.sel().clear()

    def is_enabled(self):
        return is_enabled()

    def run(self, first_byte=None, bytes_wide=None, reset=False):
        self.view = self.window.active_view()
        self.endian = hv_endianness
        byte8, bytes16, bytes32, bytes64 = None, None, None, None
        if not reset and first_byte != None and bytes_wide != None:
            byte8, bytes16, bytes32, bytes64 = self.get_bytes(int(first_byte), int(bytes_wide))
        self.display(self.window.get_output_panel('hex_viewer_inspector'), byte8, bytes16, bytes32, bytes64)


class HexDiscardEditsCommand(sublime_plugin.WindowCommand):
    def is_enabled(self):
        return is_enabled() and len(self.window.active_view().get_regions("hex_edit"))

    def run(self):
        view = self.window.active_view()
        group_size = int(view.settings().get("hex_viewer_bits", None))
        bytes_wide = int(view.settings().get("hex_viewer_actual_bytes", None))
        view.add_regions(
            "hex_edit",
            [],
            "keyword",
            sublime.DRAW_EMPTY_AS_OVERWRITE
        )
        self.window.run_command('hex_viewer', {"bits": group_size, "bytes": bytes_wide})


class HexWriterCommand(sublime_plugin.WindowCommand):
    export_path = ""
    handshake = -1

    def is_enabled(self):
        return is_enabled()

    def prepare_export(self, file_path):
        if exists(dirname(file_path)):
            self.export_path = file_path
            if exists(file_path):
                self.window.show_input_panel(
                    "Overwrite File? (yes | no):",
                    "no",
                    self.export,
                    None,
                    self.reset
                )
            else:
                self.export("yes")

    def export(self, save):
        if self.handshake != -1 and self.handshake == self.view.id():
            if save == "yes":
                try:
                    with open(self.export_path, "wb") as bin:
                        r_buffer = self.view.split_by_newlines(sublime.Region(0, self.view.size()))
                        for line in r_buffer:
                            data = re.sub(r'[\da-z]{8}:[\s]{2}((?:[\da-z]+[\s]{1})*)\s*\:[\w\W]*', r'\1', self.view.substr(line)).strip().replace(" ", "")
                            bin.write(data.decode("hex"))
                    self.view.settings().set("hex_viewer_file_name", self.export_path)
                    self.view.add_regions(
                        "hex_edit",
                        [],
                        "keyword",
                        sublime.DRAW_EMPTY_AS_OVERWRITE
                    )
                except:
                    sublime.error_message("Faild to export to " + self.export_path)
                self.reset()
            else:
                self.window.show_input_panel(
                    "Export To:",
                    self.export_path,
                    self.prepare_export,
                    None,
                    self.reset
                )
        else:
            self.reset()

    def reset(self):
        self.export_path = ""
        self.handshake = -1

    def run(self):
        self.view = self.window.active_view()

        # Identify view
        if self.handshake != -1 and self.handshake == self.view.id():
            self.reset()
        self.handshake = self.view.id()

        file_path = self.view.settings().get("hex_viewer_file_name")

        self.window.show_input_panel(
            "Export To:",
            file_path,
            self.prepare_export,
            None,
            self.reset
        )


class HexEditCommand(sublime_plugin.WindowCommand):
    handshake = -1

    def init(self):
        init_status = False
        # Get Seetings from settings file
        group_size = self.view.settings().get("hex_viewer_bits", None)
        self.bytes_wide = self.view.settings().get("hex_viewer_actual_bytes", None)
        #Process hex grouping
        if group_size != None and self.bytes_wide != None:
            self.group_size = group_size / BITS_PER_BYTE
            init_status = True
        return init_status

    def is_enabled(self):
        return is_enabled()

    def apply_edit(self, value):
        edits = ""
        # Is this the same view as earlier?
        if self.handshake != -1 and self.handshake == self.view.id():
            total_chars = self.total_bytes * 2
            selection = self.line["selection"]

            if re.match("^s:", value) != None:
                edits = value[2:len(value)].encode("hex")
            else:
                edits = value.strip().replace(" ", "").lower()

            # See if change occured and if changes are valid
            if (
                len(edits) == total_chars and
                re.match("[\da-f]{" + str(total_chars) + "}", edits) != None and
                selection != edits
            ):
                # Get previous dirty markers before modifying buffer
                regions = self.view.get_regions("hex_edit")

                # Construct old and new data for diffs
                edits = self.line["data1"] + edits + self.line["data2"]
                original = self.line["data1"] + selection + self.line["data2"]

                # Initialize
                ascii = " :"
                start = 0
                ascii_start_pos = self.ascii_pos
                hex_start_pos = self.line["range"].begin() + ADDRESS_OFFSET
                end = len(edits)
                count = 1
                change_start = None

                # Reconstruct line
                l_buffer = self.line["address"]
                while start < end:
                    byte_end = start + 2
                    value = edits[start:byte_end]

                    # Diff data and mark changed bytes
                    if value != original[start:byte_end]:
                        if change_start == None:
                            change_start = [hex_start_pos, ascii_start_pos]
                    elif change_start != None:
                        if self.view.score_selector(hex_start_pos - 1, 'raw.nibble.lower'):
                            regions.append(sublime.Region(change_start[0], hex_start_pos))
                        else:
                            regions.append(sublime.Region(change_start[0], hex_start_pos - 1))
                        regions.append(sublime.Region(change_start[1], ascii_start_pos))
                        change_start = None

                    # Write bytes and add space and at group region end
                    l_buffer += value
                    if count == self.group_size:
                        l_buffer += " "
                        hex_start_pos += 1
                        count = 0

                    # Copy valid printible ascii chars over or substitute with "."
                    dec = unpack("=B", value.decode("hex"))[0]
                    ascii += chr(dec) if dec in xrange(32, 127) else "."
                    start += 2
                    count += 1
                    hex_start_pos += 2
                    ascii_start_pos += 1

                # Check for end of line case for highlight
                if change_start != None:
                    regions.append(sublime.Region(change_start[0], hex_start_pos))
                    regions.append(sublime.Region(change_start[1], ascii_start_pos))
                    change_start = None

                # Append ascii chars to line accounting for missing bytes in line
                delta = int(self.bytes_wide) - len(edits)
                group_space = int(delta / self.group_size)
                l_buffer += " " * (group_space + delta * 2) + ascii

                # Apply buffer edit
                self.view.sel().clear()
                self.view.set_read_only(False)
                edit = self.view.begin_edit()
                self.view.replace(edit, self.line["range"], l_buffer)
                self.view.end_edit(edit)
                self.view.set_read_only(True)
                self.view.sel().add(sublime.Region(self.start_pos, self.end_pos))

                regions = underline(regions)

                # Highlight changed bytes
                self.view.add_regions(
                    "hex_edit",
                    regions,
                    "keyword",
                    sublime.DRAW_EMPTY_AS_OVERWRITE
                )

                # Update selection
                self.window.run_command('hex_nav')
        # Clean up
        self.reset()

    def reset(self):
        self.handshake = -1
        self.total_bytes = 0
        self.start_pos = -1
        self.end_pos = -1
        self.line = {}

    def ascii_to_hex(self, start, end):
        bytes = 0
        size = end - start
        ascii_range = self.view.extract_scope(start)

        # Determine if selection is within ascii range
        if start >= ascii_range.begin() and end <= ascii_range.end() + 1:
            # Single char selection or multi
            bytes = 1 if size == 0 else end - start

        if bytes != 0:
            row, column = self.view.rowcol(start)
            column = ascii_to_hex_col(column, start - ascii_range.begin(), self.group_size)
            hex_pos = self.view.text_point(row, column)
            start = hex_pos

             # Traverse row finding the specified bytes
            byte_count = bytes
            while byte_count:
                # Byte rising edge
                if self.view.score_selector(hex_pos, 'raw.nibble.upper'):
                    hex_pos += 2
                    byte_count -= 1
                    # End of selection
                    if byte_count == 0:
                        end = hex_pos - 1
                else:
                    hex_pos += 1
        return start, end, bytes

    def run(self):
        self.view = self.window.active_view()

        # Identify view
        if self.handshake != -1 and self.handshake == self.view.id():
            self.reset()
        self.handshake = self.view.id()

        # Single selection?
        if len(self.view.sel()) == 1:
            # Init
            if not self.init():
                self.reset()
                return
            sel = self.view.sel()[0]
            start = sel.begin()
            end = sel.end()
            bytes = 0

            # Get range of hex data
            line = self.view.line(start)
            hex_range = get_hex_range(line, self.group_size, self.bytes_wide)

            if self.view.score_selector(start, "comment"):
                start, end, bytes = self.ascii_to_hex(start, end)

            # Determine if selection is within hex range
            if start >= hex_range.begin() and end <= hex_range.end():
                # Adjust beginning of selection to begining of first selected byte
                if bytes == 0:
                    start, end, bytes = adjust_hex_sel(self.view, start, end, self.group_size)

                # Get general line info for diffing and editing
                if bytes != 0:
                    self.ascii_pos = hex_range.end() + ASCII_OFFSET
                    self.total_bytes = bytes
                    self.start_pos = start
                    self.end_pos = end + 1
                    self.line = {
                        "range": line,
                        "address": self.view.substr(sublime.Region(line.begin(), line.begin() + ADDRESS_OFFSET)),
                        "selection": self.view.substr(sublime.Region(start, end + 1)).strip().replace(" ", ""),
                        "data1": self.view.substr(sublime.Region(hex_range.begin(), start)).strip().replace(" ", ""),
                        "data2": self.view.substr(sublime.Region(end + 1, hex_range.end() + 1)).strip().replace(" ", "")
                    }

                    # Send selected bytes to be edited
                    self.window.show_input_panel(
                        "Edit",
                        self.view.substr(sublime.Region(start, end + 1)).strip(),
                        self.apply_edit,
                        None,
                        None
                    )


class HexGoToCommand(sublime_plugin.WindowCommand):
    def go_to_address(self, address):
        #init
        view = self.window.active_view()

        # Adress offset for line
        group_size = view.settings().get("hex_viewer_bits", None)
        bytes_wide = view.settings().get("hex_viewer_actual_bytes", None)
        if group_size == None and bytes_wide == None:
            return
        group_size = group_size / BITS_PER_BYTE

        # Go to address
        try:
            # Address wanted
            wanted = int(address, 16)
            # Calculate row
            row = int(wanted / (bytes_wide))
            # Byte offset into final row
            byte = wanted % (bytes_wide)
            #   Calculate byte number              Offset Char
            #
            #  wanted_char      byte
            # ------------ = -----------  => wanted_char + 11 = column
            #  total_chars   total_bytes
            #
            column = int((float(byte) / group_size) * ((group_size) * 2 + 1)) + ADDRESS_OFFSET

            # Go to address and focus
            pt = view.text_point(row, column)
            view.sel().clear()
            view.sel().add(pt)
            view.show_at_center(pt)
            # Highlight
            self.window.run_command('hex_nav')
        except:
            pass

    def is_enabled(self):
        return is_enabled()

    def run(self):
        self.window.show_input_panel(
            "Find: 0x",
            "",
            self.go_to_address,
            None,
            None
        )

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import os
from encryption import SteganographyEncoder
from decryption import SteganographyDecoder
import threading

class SteganoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        
        self.title("Secure Steganography App")
        self.geometry("800x600")
        self.configure(bg="#2C3E50")
        
        self.encoder = SteganographyEncoder()
        self.decoder = SteganographyDecoder()
        
        self.create_styles()
        self.create_widgets()
        
    def create_styles(self):
        style = ttk.Style()
        style.configure(
            "Custom.TButton",
            padding=10,
            font=("Helvetica", 12),
            background="#4a90e2"
        )
        style.configure(
            "Custom.TLabel",
            font=("Helvetica", 12),
            background="#f0f0f0"
        )
        style.configure(
            "Custom.TFrame",
            background="#f0f0f0"
        )

    def create_widgets(self):
        main_frame = ttk.Frame(self, style="Custom.TFrame", padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Mode selection
        self.mode_var = tk.StringVar(value="encode")
        ttk.Radiobutton(
            main_frame,
            text="Encode",
            variable=self.mode_var,
            value="encode",
            command=self.update_mode
        ).pack(pady=5)
        ttk.Radiobutton(
            main_frame,
            text="Decode",
            variable=self.mode_var,
            value="decode",
            command=self.update_mode
        ).pack(pady=5)
        
        # Image selection
        ttk.Button(
            main_frame,
            text="Select Image",
            command=self.select_image,
            style="Custom.TButton"
        ).pack(pady=10)
        
        # Image preview
        self.preview_label = ttk.Label(main_frame)
        self.preview_label.pack(pady=10)
        
        # Message input
        self.message_frame = ttk.Frame(main_frame, style="Custom.TFrame")
        ttk.Label(
            self.message_frame,
            text="Enter Secret Message:",
            style="Custom.TLabel"
        ).pack(pady=5)
        self.message_text = tk.Text(self.message_frame, height=4, width=40)
        self.message_text.pack(pady=5)
        
        # Password entry
        self.password_frame = ttk.Frame(main_frame, style="Custom.TFrame")
        ttk.Label(
            self.password_frame,
            text="Password (Required):",
            style="Custom.TLabel"
        ).pack(pady=5)
        self.password_entry = ttk.Entry(self.password_frame, show="*")
        self.password_entry.pack(pady=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(
            main_frame,
            mode='indeterminate',
            length=300
        )
        
        # Action button
        self.action_button = ttk.Button(
            main_frame,
            text="Encode Message",
            command=self.process_image,
            style="Custom.TButton"
        )
        
        # Pack frames
        self.message_frame.pack(pady=10)
        self.password_frame.pack(pady=10)
        self.progress.pack(pady=10)
        self.action_button.pack(pady=10)
        
        self.update_mode()

    def update_mode(self):
        mode = self.mode_var.get()
        if mode == "encode":
            self.message_frame.pack(pady=10)
            self.action_button.configure(text="Encode Message")
        else:
            self.message_frame.pack_forget()
            self.action_button.configure(text="Decode Message")

    def select_image(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")]
        )
        if file_path:
            self.image_path = file_path
            self.update_preview()

    def update_preview(self):
        try:
            image = Image.open(self.image_path)
            image.thumbnail((200, 200))
            photo = ImageTk.PhotoImage(image)
            self.preview_label.configure(image=photo)
            self.preview_label.image = photo
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {str(e)}")

    def process_image(self):
        if not hasattr(self, 'image_path'):
            messagebox.showerror("Error", "Please select an image first")
            return
            
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password is required")
            return
            
        self.progress.start()
        threading.Thread(target=self._process_image_thread).start()

    def _process_image_thread(self):
        try:
            mode = self.mode_var.get()
            password = self.password_entry.get()
            
            if mode == "encode":
                message = self.message_text.get("1.0", tk.END).strip()
                if not message:
                    self.show_error("Please enter a message to encode")
                    return
                
                if not self.encoder.can_encode(self.image_path, message):
                    self.show_error("Message is too large for this image")
                    return
                
                encoded_image = self.encoder.encode(
                    self.image_path,
                    message,
                    password
                )
                
                save_path = filedialog.asksaveasfilename(
                    defaultextension=".png",
                    filetypes=[("PNG files", "*.png")]
                )
                if save_path:
                    encoded_image.save(save_path)
                    self.show_success("Message encoded successfully!")
                
            else:  # decode
                try:
                    message = self.decoder.decode(self.image_path, password)
                    self.show_decoded_message(message)
                except ValueError as e:
                    self.show_error(str(e))
                except Exception as e:
                    self.show_error(f"Failed to decode message: {str(e)}")
                    
        except Exception as e:
            self.show_error(f"Error: {str(e)}")
        finally:
            self.progress.stop()

    def show_error(self, message):
        self.after(0, lambda: messagebox.showerror("Error", message))

    def show_success(self, message):
        self.after(0, lambda: messagebox.showinfo("Success", message))

    def show_decoded_message(self, message):
        def show():
            top = tk.Toplevel(self)
            top.title("Decoded Message")
            top.geometry("400x300")
            
            text = tk.Text(top, wrap=tk.WORD, padx=10, pady=10)
            text.pack(fill=tk.BOTH, expand=True)
            text.insert("1.0", message)
            text.configure(state="disabled")
            
            ttk.Button(
                top,
                text="Close",
                command=top.destroy,
                style="Custom.TButton"
            ).pack(pady=10)
            
        self.after(0, show)

if __name__ == "__main__":
    app = SteganoApp()
    app.mainloop()
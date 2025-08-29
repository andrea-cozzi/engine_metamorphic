from pathlib import Path
import traceback
import lief as lf
import logging


logger = logging.getLogger(__name__)

class BinaryCreator:

    def __init__(self):
        raise RuntimeError("BinaryCreator is a static class")
    
    @staticmethod
    def create_binary(
            binary: lf.Binary,
            new_bytes: bytes,
            filename: str
    ) -> bool:
        try:
            is_pe : bool = isinstance(binary, lf.PE.Binary)
            is_elf: bool = isinstance(binary, lf.ELF.Binary)

            if not (is_pe or is_elf):
                raise TypeError("Binary {filename} format is not supported".format(filename=filename))
            
            if not binary.has_section(".text"):
                raise ValueError(f"Binary {filename} does not have .text section")

            text_section = binary.get_section(".text")
            ori_size : int = len(text_section.content)
            new_size : int = len(new_bytes)


            if new_size <= ori_size:
                text_section.content = list(new_bytes) + [0] * (ori_size - new_size)
                logger.info("Overwrite diretto della .text")
                return BinaryCreator._write_binary(
                    binary=binary,
                    filename=filename,
                    is_pe=is_pe
                )


            #Nuova .text più grande, creo sezione eseguibile nuova e aggiorno EP
            base_name: str = ".text_ext"
            sec_name: str = base_name
            counter: int = 1

            while any(s.name == sec_name for s in binary.sections):
                sec_name = f"{base_name}_counter"
                counter+=1

            if is_pe:
                new_sec = lf.PE.Section(sec_name)
                new_sec.content = list(new_bytes)
                new_sec.characteristics = (
                    lf.PE.Section.CHARACTERISTICS.MEM_EXECUTE |
                    lf.PE.Section.CHARACTERISTICS.MEM_READ
                )

                new_sec = BinaryCreator._align_pe_section(new_sec, binary.optional_header.section_alignment, binary.optional_header.file_alignment)

                # Aggiungi sezione e aggiorna entrypoint
                added = binary.add_section(new_sec, lf.PE.SECTION_TYPES.TEXT)
                binary.optional_header.address_of_entry_point = added.virtual_address
                
            elif is_elf:
                pass
            else:
                raise RuntimeError("Configuration: is_pe - is_elf cannot happend")

        except Exception as e:
            logger.error(traceback.print_exc())
            return False
        

    @staticmethod
    def _align_pe_section(section: lf.PE.Section, section_alignment: int, file_alignment: int) -> lf.PE.Section:
        """
        Allinea la sezione PE sia in virtual size che in raw size secondo:
        - section_alignment: allineamento in memoria virtuale
        - file_alignment: allineamento su file
        Riempie con zeri se necessario.
        """
        content_len = len(section.content)

        # Allinea la virtual size
        virtual_size = (content_len + section_alignment - 1) // section_alignment * section_alignment
        # Allinea la raw size
        raw_size = (content_len + file_alignment - 1) // file_alignment * file_alignment

        # Padding per la virtual size (in memoria)
        if virtual_size > content_len:
            section.content += [0] * (virtual_size - content_len)

        # Nota: LIEF si occupa di settare raw_size correttamente in builder
        # ma possiamo comunque assicurare che il contenuto sia almeno raw_size
        if raw_size > len(section.content):
            section.content += [0] * (raw_size - len(section.content))

        return section
            
    @staticmethod
    def _write_binary(
        binary: lf.Binary,
        filename: str,
        is_pe : bool
    ) -> bool:
        #TODO inserire la costante del Path
        output_path  = Path() 
        output_path.mkdir(parents=True, exist_ok=True)
        out_dir = output_path / f"{filename}_mutated.exe" if is_pe else f"{filename}_mutated"
        
        try:    
            if is_pe:
                builder = lf.PE.Builder(binary)
                builder.build()
                builder.write(str(out_dir))
            else:
                binary.write(str(out_dir))
                out_dir.chmod(0o755)
            logger.info(f"File scritto: {out_dir}")
            return True

        except Exception as e:
            logger.error(traceback.print_exc())
            return False

        
